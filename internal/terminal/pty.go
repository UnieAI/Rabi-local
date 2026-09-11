// Package terminal 把「使用者自己在鍵盤上打字」的那種終端機，搬到這台電腦上。
//
// 它**不是** runner.Exec 多加幾個參數。exec 是一句指令一個答案；終端機沒有
// 請求／回應這種形狀 —— shell 想說話的時候就說，而且說在那個開啟它的呼叫早就
// 回去之後很久。三個差別是整個檔案的理由：
//
//   - exec 跑 `bash -lc`，每台機器都一樣，因為**模型**需要一個可預期的 shell。
//     人要的正好相反：他自己的提示字元、他的 alias、他的補完。所以這裡的 shell
//     **不帶任何旗標** —— 在 PTY 上那就是互動式，於是它會去讀 `~/.bashrc`，
//     oh-my-bash、starship 和每一個 alias 都在那裡。`-l` 會變成 login shell、
//     改讀 `~/.bash_profile`、跳過 `.bashrc`，然後把一個精心設定過的人丟回
//     一個光禿禿的 `$`。
//   - 終端機的命是**工作階段**的命，不是一輪對話的命。跑著 `npm run dev` 的
//     shell 不可以因為使用者換了一個對話就死掉（見 Service 的說明）。
//   - 輸出是**原始位元組**，一路不解碼。一個多位元組字元被切在兩次 PTY 讀取
//     之間是常態不是例外，中間任何一層先解碼，就會變成後面沒有人救得回來的
//     替代字元。所以 Event.Data 是 []byte，base64 是 dispatch.go 那一層（線路
//     的事）才做的。
//
// 規格來源是 TypeScript 版的 `runtime/apps/ava-local/src/{pty,terminal}.ts`
// 與 `tool-host.ts` 的 terminal* 幾個 op。這個 Go 版多做了兩件 TS 版做不到的事：
//
//   - **Windows 真的有終端機。** TS 版靠 bun:ffi 呼叫 libc 的 openpty／
//     login_tty，Windows 上沒有那組東西，所以它直接回 pty_unsupported。Go 這裡
//     走 ConPTY（`CreatePseudoConsole` ＋ `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`），
//     用 build tag 分檔，見 pty_windows.go。
//   - **零 cgo。** 三平台交叉編譯是這個執行檔的前提（一台 Linux 機器要生出
//     macOS 與 Windows 的檔），cgo 會毀掉它。unix 那側只用標準函式庫的
//     `syscall`（ioctl／Setsid／Setctty），Windows 那側只用 `syscall.NewLazyDLL`
//     叫 kernel32 —— 兩邊都不需要 cgo，也沒有引入任何第三方相依。
package terminal

import (
	"errors"
	"fmt"
)

// Spec 是開一個虛擬終端機所需要的全部條件。
type Spec struct {
	// Argv 是要跑的程式，argv[0] 就是程式本身。**不要在這裡加旗標**（見套件說明）。
	Argv []string
	// Cwd 已經是解析過、而且確認落在授權資料夾裡的絕對路徑。
	Cwd string
	// Env 是這個 shell 會看到的全部環境變數（不是「額外的」，是全部）。
	Env        map[string]string
	Cols, Rows int
}

// Handle 是一個活著的虛擬終端機，由平台各自實作。
//
// 讀寫刻意做成 io 的形狀而不是回呼：讀的那一側只有一個 goroutine（Service 的
// 泵），所以輸出的順序不必另外保證；而「終端機結束了」在 Linux 上是讀到 EIO、
// 在 macOS 上是讀到 EOF、在 Windows 上是 pipe 斷掉 —— 三種都由實作翻成 io.EOF。
type Handle interface {
	// Pid 是 shell 的行程編號（unix 上同時也是它的 process group／session id）。
	Pid() int
	// Read 讀終端機產生的原始位元組。終端機結束時回 io.EOF。
	Read(p []byte) (int, error)
	// Write 送出使用者打的原始位元組。什麼都不會被加上去 —— 連換行都不會。
	Write(p []byte) (int, error)
	// Resize 告訴終端機視窗變大小了。
	Resize(cols, rows int) error
	// SignalGroup 對 shell **和它啟動的一切**送訊號。
	SignalGroup(sig GroupSignal) error
	// Wait 等到 shell 真的結束，回傳它的離開碼。
	Wait() (int, error)
	// Close 放掉這一側的資源。Read 會因此解除阻塞。
	Close() error
}

// GroupSignal 是送得到「整個 process group」的那幾個訊號。
//
// 只有三個，而且刻意不用 os.Signal：Windows 根本沒有訊號這個東西，一個帶著
// syscall.Signal 的介面會在那裡變成一個假裝得很像的謊。
type GroupSignal string

const (
	// SignalHup 是「這個終端機關掉了」—— 關閉一個終端機用的就是它。
	SignalHup GroupSignal = "SIGHUP"
	// SignalTerm 請它收一收。
	SignalTerm GroupSignal = "SIGTERM"
	// SignalKill 不留餘地。
	SignalKill GroupSignal = "SIGKILL"
)

// Backend 是這台機器上開終端機的方法。
type Backend interface {
	// Name 是給稽核與診斷看的後端名稱（"pty" / "conpty"）。
	Name() string
	Open(Spec) (Handle, error)
}

// 這些代碼會原樣回到雲端，前端靠它們分岔。**不要改字面值** ——
// TypeScript 版的 daemon 回的就是這幾個（terminal.ts 的 TerminalError）。
const (
	CodeDisabled    = "terminals_disabled"
	CodeNoTerminal  = "no_terminal"
	CodeTooMany     = "too_many_terminals"
	CodeNoShell     = "no_shell"
	CodeExited      = "exited"
	CodeUnsupported = "pty_unsupported"
	CodeOpenFailed  = "pty_open_failed"
	CodeSpawnFailed = "pty_spawn_failed"
	CodeOutsideRoot = "outside_root"
	CodeBadRequest  = "bad_request"
	CodeExists      = "terminal_exists"
	CodeApprovalReq = "approval_required"
	CodeApprovalBad = "approval_rejected"
)

// Error 是一個呼叫端不必讀句子就能分岔的失敗。
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func errf(code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// CodeOf 從任何一個 error 取出它的代碼；不是這個套件的錯誤就回 "internal"。
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "internal"
}

// DefaultBackend 回傳這台機器上可用的後端；開不了就回 nil 與原因。
//
// 刻意回 (nil, error) 而不是 panic：一台開不了 PTY 的機器**其他每一個 op 都
// 還要能用**，而且雲端那側要看到的是「這台機器開不了終端機」這個事實，不是一個
// 掛掉的 daemon。
func DefaultBackend() (Backend, error) { return newPlatformBackend() }
