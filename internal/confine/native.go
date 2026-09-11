package confine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"
)

// Kind 是原生關押的種類。
type Kind string

const (
	// KindNone 這台機器沒有可用的原生關押。
	KindNone Kind = "none"
	// KindBwrap Linux 的 bubblewrap。
	KindBwrap Kind = "bwrap"
	// KindSandboxExec macOS 內建的 Seatbelt。
	KindSandboxExec Kind = "sandbox-exec"
)

// LookPath 是「這個執行檔在不在」的注入點。預設就是 exec.LookPath。
type LookPath func(bin string) (string, error)

func realLookPath(bin string) (string, error) { return exec.LookPath(bin) }

// nativeKindFor 說的是「這個作業系統**會**用哪一種」，不是「這台機器有沒有」。
//
// 分成兩件事是因為它們的答案來源不同：前者是平台的事實（純函式，三個平台都
// 驗得到），後者要去機器上找執行檔（見各平台的 detect 檔）。
func nativeKindFor(goos string) Kind {
	switch goos {
	case "darwin":
		return KindSandboxExec
	case "linux":
		return KindBwrap
	default:
		// Windows 與其他平台：沒有不必安裝就能用的東西。見 native_windows.go。
		return KindNone
	}
}

// secretDirsFor 是連**讀**都不給的路徑（相對家目錄）。
//
// 收在一個吃 goos 的純函式裡，是為了讓 macOS 的 profile 在 Linux 上也測得到 ——
// 用 build tag 分檔的話，另外兩個平台的規則在 CI 上永遠沒有人驗。
func secretDirsFor(goos string) []string {
	common := []string{".ssh", ".aws", ".gnupg", ".config/gh", ".kube", ".docker"}
	if goos == "darwin" {
		return append(common, "Library/Keychains")
	}
	return common
}

// BwrapArgs 組出 bwrap 的參數：root 可寫，其餘唯讀，憑證目錄直接遮掉。
//
// exists 可以注入是為了測試，但它**不是**只為了測試：`--ro-bind / /` 之後
// 整棵樹是唯讀的，所以 bwrap 替一個**不存在**的目錄掛 tmpfs 時會先 mkdir，
// 然後失敗：
//
//	bwrap: Can't mkdir /home/u/.aws: Read-only file system
//
// 而那不是「這個目錄沒遮到」，是**整個 bwrap 起不來**，於是每一條指令都死。
// 2026-09-11 在真的機器上跑才發現 —— 純粹組參數的測試全綠。
//
// 不存在的目錄本來就沒有東西要遮，跳過它是對的。
func BwrapArgs(root, home string, argv []string, cwd string, exists func(string) bool) []string {
	if exists == nil {
		exists = func(p string) bool { _, err := os.Lstat(p); return err == nil }
	}
	args := []string{
		// 父行程死掉時整個沙盒跟著收 —— 不做的話 daemon 關掉之後，
		// 使用者電腦上還有東西在動，而且沒有人殺得掉。
		"--die-with-parent",
		// 整顆根目錄唯讀掛進去：toolchain（node、python、git、系統函式庫）都在
		// 外面，讀不到的話 agent 第一步就失敗。見套件說明「關的是寫，不是讀」。
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		// 授權資料夾是唯一可寫的地方。
		// 順序有意義：它排在 --tmpfs /tmp 後面，授權資料夾剛好在 /tmp 底下時
		// 才不會被那層 tmpfs 蓋掉。
		"--bind", root, root,
	}
	// 憑證目錄用空的 tmpfs 蓋掉 —— 存在但空的，比「不存在」少一點壞掉的機會。
	// 只遮**真的存在**的那些，理由見上面。
	for _, d := range secretDirsFor("linux") {
		p := path.Join(home, d)
		if exists(p) {
			args = append(args, "--tmpfs", p)
		}
	}
	args = append(args, "--chdir", cwd, "--")
	return append(args, argv...)
}

// MacProfile 組出 sandbox-exec 吃的 SBPL。
//
// `(allow default)` 開頭再逐項 deny，而不是 deny 開頭再逐項 allow：後者要把
// 每一個系統呼叫、每一個 dyld 路徑都列出來，而漏掉一個的症狀是二進位檔根本
// 起不來、錯誤訊息又完全看不出原因。這一層要的是寫入圍籬，不是最小權限。
func MacProfile(root, home string) string {
	lit := func(p string) string { return strconv.Quote(path.Clean(p)) }
	secrets := make([]string, 0, len(secretDirsFor("darwin")))
	for _, d := range secretDirsFor("darwin") {
		secrets = append(secrets, "  (subpath "+lit(path.Join(home, d))+")")
	}
	return strings.Join([]string{
		"(version 1)",
		"(allow default)",
		"",
		";; 寫入：只有授權資料夾與暫存目錄",
		"(deny file-write*)",
		"(allow file-write* (subpath " + lit(root) + "))",
		`(allow file-write* (subpath "/private/tmp") (subpath "/private/var/tmp") (subpath "/dev"))`,
		"",
		";; 憑證：連讀都不給",
		"(deny file-read*",
		strings.Join(secrets, "\n"),
		")",
		"",
	}, "\n")
}

// NativeOptions 是建立原生關押時可以覆寫的東西。空值就是合理的預設。
type NativeOptions struct {
	// Bin 是關押程式的絕對路徑（bwrap / sandbox-exec）。空的話就用名字，
	// 交給 PATH 去找。
	Bin string
	// Home 是家目錄，用來算憑證目錄的位置。空的話問作業系統。
	Home string
	// ProfileDir 是 macOS profile 要寫到哪裡。空的話每次開一個暫存目錄。
	ProfileDir string
	// Exists 是「這個路徑存不存在」，見 BwrapArgs 的說明。
	Exists func(string) bool
}

type native struct {
	kind Kind
	opts NativeOptions
}

func (n *native) Name() string { return string(n.kind) }

// When 見 Mode：這一層幾乎不花成本，不預設開等於沒做。
func (n *native) When() Mode { return ModeAlways }

func (n *native) bin(fallback string) string {
	if n.opts.Bin != "" {
		return n.opts.Bin
	}
	return fallback
}

func (n *native) home() string {
	if n.opts.Home != "" {
		return n.opts.Home
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	// 家目錄問不到時給一個**不會誤中**的值：算出來的憑證目錄不存在，
	// 於是不會有遮蔽 —— 但也不會誤遮到真的目錄。這種情況本來就極少見。
	return "/nonexistent"
}

func (n *native) Wrap(argv []string, opts Options) (Command, error) {
	if len(argv) == 0 {
		return Command{}, fmt.Errorf("confine: 沒有指定要執行什麼")
	}
	if opts.Root == "" {
		return Command{}, fmt.Errorf("confine: 沒有授權資料夾，沒有東西可以當圍籬")
	}
	cwd := opts.Cwd
	if cwd == "" {
		cwd = opts.Root
	}
	switch n.kind {
	case KindBwrap:
		args := BwrapArgs(opts.Root, n.home(), argv, cwd, n.opts.Exists)
		return Command{Argv: append([]string{n.bin("bwrap")}, args...), Dir: cwd}, nil
	case KindSandboxExec:
		// sandbox-exec 吃的是檔案或 -p 字串。用檔案：profile 裡有絕對路徑，
		// 塞進命令列會遇到引號與長度的問題，而且日誌裡會出現一大坨。
		dir := n.opts.ProfileDir
		if dir == "" {
			d, err := os.MkdirTemp("", "ava-sbpl-")
			if err != nil {
				return Command{}, fmt.Errorf("confine: 寫不出 sandbox profile：%w", err)
			}
			dir = d
		}
		file := path.Join(dir, "ava.sb")
		if err := os.WriteFile(file, []byte(MacProfile(opts.Root, n.home())), 0o600); err != nil {
			return Command{}, fmt.Errorf("confine: 寫不出 sandbox profile：%w", err)
		}
		argv = append([]string{n.bin("sandbox-exec"), "-f", file}, argv...)
		return Command{Argv: argv, Dir: cwd}, nil
	default:
		return Command{}, fmt.Errorf("confine: 不認得的關押種類 %q", string(n.kind))
	}
}

// NewNative 建一個原生關押。
//
// 呼叫端通常不需要它 —— Choose() 會挑好。直接用它是為了測試，或者為了
// 在明確知道機器上有什麼的情況下指定一種。
func NewNative(kind Kind, opts NativeOptions) (Confinement, error) {
	if kind != KindBwrap && kind != KindSandboxExec {
		return nil, fmt.Errorf("confine: %q 不是原生關押", string(kind))
	}
	return &native{kind: kind, opts: opts}, nil
}

// DetectNative 找出這台機器上有哪一種原生關押。
//
// 找不到就回 KindNone 與一句**照實講**的理由 —— 這裡不偷偷退回「沒有關押」
// 再假裝一切正常，因為那正是「以為有保護，其實沒有」的來源。
func DetectNative() (kind Kind, bin string, why string) {
	return detectNative(realLookPath)
}

// probeErr 把一次失敗的偵測執行翻成一句看得懂的話。
//
// exec 的預設錯誤是 "exit status 1"，那對使用者毫無用處；真正的原因一律在
// stderr（"setting up uid map: Permission denied" 這種）。偵測失敗的訊息會
// 直接出現在畫面上，所以要帶著原因。
func probeErr(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%s", strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}

// runWithTimeout 跑一個外部指令並收集 stdout。偵測用的東西一律要有逾時：
// 一個沒有 daemon 的 docker CLI 可以卡很久，而那會變成「桌面程式打不開」。
func runWithTimeout(d time.Duration, bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).Output()
	return string(out), err
}
