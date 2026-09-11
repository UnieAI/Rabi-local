package confine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 這一支測的是「在哪台機器上跑都一樣」的那一半：偵測的規則與參數組裝。
//
// 只有這一半的話，這個功能可以整個是假的而測試全綠 —— 參數組得漂漂亮亮，
// 而 bwrap 根本沒有把那個目錄擋住。真的把指令關起來跑的那一半在
// bwrap_exec_linux_test.go，**那一支才是重點**。

func TestNativeKindFor(t *testing.T) {
	cases := map[string]Kind{
		"darwin":  KindSandboxExec,
		"linux":   KindBwrap,
		"windows": KindNone, // 明著說沒有，不可以退回一個「看起來有關押」的東西
		"freebsd": KindNone,
	}
	for goos, want := range cases {
		if got := nativeKindFor(goos); got != want {
			t.Errorf("%s: 得到 %q，預期 %q", goos, got, want)
		}
	}
}

func TestSecretDirs(t *testing.T) {
	// 鑰匙圈是 macOS 才有的東西，Linux 列它沒有意義（而且會多一次 tmpfs）。
	if !contains(secretDirsFor("darwin"), "Library/Keychains") {
		t.Error("macOS 的清單少了鑰匙圈")
	}
	if contains(secretDirsFor("linux"), "Library/Keychains") {
		t.Error("Linux 的清單不該有鑰匙圈")
	}
	for _, goos := range []string{"linux", "darwin"} {
		for _, want := range []string{".ssh", ".aws", ".gnupg"} {
			if !contains(secretDirsFor(goos), want) {
				t.Errorf("%s 的清單少了 %s", goos, want)
			}
		}
	}
}

func TestBwrapArgs(t *testing.T) {
	// 第五個參數是「這個路徑存不存在」，這裡一律當成存在，才驗得到遮蔽那幾行。
	args := BwrapArgs("/home/u/work", "/home/u", []string{"echo", "hi"}, "/home/u/work", func(string) bool { return true })
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--ro-bind / /",                    // toolchain 讀得到
		"--bind /home/u/work /home/u/work", // 唯一可寫的地方
		"--tmpfs /home/u/.ssh",
		"--tmpfs /home/u/.aws",
		"--die-with-parent",
		"--chdir /home/u/work",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("參數裡少了 %q\n實際：%s", want, joined)
		}
	}
	// 指令本身要在 `--` 之後，否則參數會被 bwrap 自己吃掉。
	sep := indexOf(args, "--")
	if sep < 0 {
		t.Fatal("沒有 -- 分隔符")
	}
	if got := args[sep+1:]; len(got) != 2 || got[0] != "echo" || got[1] != "hi" {
		t.Errorf("-- 之後應該剛好是要執行的指令，得到 %v", got)
	}
}

func TestBwrapArgsSkipsMissingSecretDirs(t *testing.T) {
	// `--ro-bind / /` 之後掛 tmpfs 要先 mkdir，而那是唯讀的。失敗的不是遮蔽，
	// 是整個 bwrap，於是每一條指令都死。2026-09-11 真的跑過才發現。
	args := BwrapArgs("/home/u/work", "/home/u", []string{"true"}, "/home/u/work", func(string) bool { return false })
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--tmpfs /home/u/.ssh") {
		t.Error("替不存在的目錄掛了 tmpfs —— 整個 bwrap 會起不來")
	}
	// 該有的還是要有。
	if !strings.Contains(joined, "--bind /home/u/work /home/u/work") {
		t.Error("跳過遮蔽的同時把圍籬也弄丟了")
	}
}

func TestBwrapBindComesAfterTmpfsTmp(t *testing.T) {
	// bwrap 是照順序套用的。授權資料夾剛好在 /tmp 底下時（測試、暫存專案很常見），
	// --bind 排在 --tmpfs /tmp 前面的話會被那層 tmpfs 蓋掉，
	// 於是使用者的檔案寫進一個開機就消失的地方。
	args := BwrapArgs("/tmp/work", "/home/u", []string{"true"}, "/tmp/work", func(string) bool { return false })
	tmpfs, bind := -1, -1
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--tmpfs" && args[i+1] == "/tmp" {
			tmpfs = i
		}
		if args[i] == "--bind" && args[i+1] == "/tmp/work" {
			bind = i
		}
	}
	if tmpfs < 0 || bind < 0 {
		t.Fatalf("找不到 --tmpfs /tmp 或 --bind：%v", args)
	}
	if bind < tmpfs {
		t.Error("--bind 排在 --tmpfs /tmp 前面，授權資料夾會被蓋掉")
	}
}

func TestMacProfile(t *testing.T) {
	p := MacProfile("/Users/u/work", "/Users/u")
	for _, want := range []string{
		"(deny file-write*)",
		`(allow file-write* (subpath "/Users/u/work"))`,
		"(deny file-read*",
		`"/Users/u/.ssh"`,
		`"/Users/u/Library/Keychains"`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile 裡少了 %q\n實際：\n%s", want, p)
		}
	}
	// allow default 開頭：deny 開頭的 profile 會讓二進位檔根本起不來，
	// 而症狀完全看不出原因。
	if !strings.HasPrefix(p, "(version 1)\n(allow default)") {
		t.Error("profile 不是 allow default 開頭")
	}
	// 暫存目錄要可寫，否則幾乎每個編譯器都會壞。
	if !strings.Contains(p, "/private/tmp") {
		t.Error("profile 沒有放行暫存目錄")
	}
}

func TestNativeAlwaysOn(t *testing.T) {
	// on-request 的話絕大多數指令是完全沒有關押的 —— 見 Mode 的說明。
	c, err := NewNative(KindBwrap, NativeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if c.When() != ModeAlways {
		t.Errorf("原生關押應該預設就開，得到 %q", c.When())
	}
	if c.Name() != "bwrap" {
		t.Errorf("名字要說實話，得到 %q", c.Name())
	}
	if _, err := NewNative(KindNone, NativeOptions{}); err == nil {
		t.Error("KindNone 不該建得出關押")
	}
}

func TestNativeWrapBwrap(t *testing.T) {
	c, err := NewNative(KindBwrap, NativeOptions{Bin: "/usr/bin/bwrap", Home: "/home/u", Exists: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := c.Wrap([]string{"bash", "-lc", "make"}, Options{Root: "/home/u/work", Cwd: "/home/u/work/sub"})
	if err != nil {
		t.Fatal(err)
	}
	bin, args := cmd.Split()
	if bin != "/usr/bin/bwrap" {
		t.Errorf("執行的應該是 bwrap，得到 %q", bin)
	}
	if !strings.Contains(strings.Join(args, " "), "--chdir /home/u/work/sub") {
		t.Error("工作目錄沒有跟著進去")
	}
	if cmd.Dir != "/home/u/work/sub" {
		t.Errorf("主機端 cwd 應該原樣保留，得到 %q", cmd.Dir)
	}
}

func TestNativeWrapSandboxExec(t *testing.T) {
	dir := t.TempDir()
	c, err := NewNative(KindSandboxExec, NativeOptions{Bin: "/usr/bin/sandbox-exec", Home: "/Users/u", ProfileDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := c.Wrap([]string{"bash", "-lc", "make"}, Options{Root: "/Users/u/work", Cwd: "/Users/u/work"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/sandbox-exec", "-f", filepath.Join(dir, "ava.sb"), "bash", "-lc", "make"}
	if strings.Join(cmd.Argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv 不對：\n得到 %v\n預期 %v", cmd.Argv, want)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "ava.sb"))
	if err != nil {
		t.Fatalf("profile 沒寫出來：%v", err)
	}
	if !strings.Contains(string(raw), `(subpath "/Users/u/work")`) {
		t.Error("profile 裡沒有授權資料夾")
	}
	st, err := os.Stat(filepath.Join(dir, "ava.sb"))
	if err != nil {
		t.Fatal(err)
	}
	// profile 裡有使用者的家目錄結構，不必給別人看。
	if st.Mode().Perm() != 0o600 {
		t.Errorf("profile 權限應該是 0600，得到 %v", st.Mode().Perm())
	}
}

func TestWrapRefusesNonsense(t *testing.T) {
	c, err := NewNative(KindBwrap, NativeOptions{Bin: "bwrap"})
	if err != nil {
		t.Fatal(err)
	}
	// 沒有授權資料夾就沒有圍籬可言。這種時候**不可以**回一個沒有關押的
	// 指令當作「盡力了」—— 呼叫端會以為它被關住了。
	if _, err := c.Wrap([]string{"true"}, Options{Root: ""}); err == nil {
		t.Error("沒有 root 竟然包得出東西")
	}
	if _, err := c.Wrap(nil, Options{Root: "/home/u/work"}); err == nil {
		t.Error("沒有 argv 竟然包得出東西")
	}
}

func TestNoopIsHonest(t *testing.T) {
	c := Noop()
	if c.Name() != "none" {
		t.Errorf("沒有關押就要叫 none，得到 %q", c.Name())
	}
	cmd, err := c.Wrap([]string{"echo", "hi"}, Options{Root: "/r", Cwd: "/r/sub"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Argv) != 2 || cmd.Dir != "/r/sub" {
		t.Errorf("noop 不該改動任何東西，得到 %v / %q", cmd.Argv, cmd.Dir)
	}
}

func TestPostureTellsTheTruth(t *testing.T) {
	bw, err := NewNative(KindBwrap, NativeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := PostureOf(bw, "/home/u/work", false)
	if p.Confinement != "bwrap" || p.ConfinementWhen != ModeAlways || !p.SecretsHidden {
		t.Errorf("原生關押的 posture 不對：%+v", p)
	}
	if p.OutboundRedaction {
		t.Error("Go 版還沒有出站遮蔽，posture 不可以說有")
	}
	if p.GrantedRoot != "/home/u/work" {
		t.Error("授權資料夾沒有報上去")
	}

	// 沒有關押的機器要看得出自己沒有 —— 這一條是整份 posture 的重點。
	n := PostureOf(Noop(), "/home/u/work", false)
	if n.Confinement != "none" || n.SecretsHidden {
		t.Errorf("沒有關押卻報成有：%+v", n)
	}

	// 容器是 on-request：憑證目錄在**沒有被要求**的指令裡是讀得到的，
	// 所以 secretsHidden 只有 always 那一種才算數。
	cn := PostureOf(NewContainer(ContainerOptions{}), "/home/u/work", true)
	if cn.ConfinementWhen != ModeOnRequest || cn.SecretsHidden {
		t.Errorf("容器的 posture 不對：%+v", cn)
	}
	if !cn.OutboundRedaction {
		t.Error("遮蔽是參數，傳 true 就該是 true")
	}
}

func contains(list []string, want string) bool {
	return indexOf(list, want) >= 0
}

func indexOf(list []string, want string) int {
	for i, s := range list {
		if s == want {
			return i
		}
	}
	return -1
}
