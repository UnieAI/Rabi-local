//go:build windows

package terminal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Windows 的終端機走 ConPTY，跟 unix 完全不是同一套東西。
//
// # 形狀差在哪裡
//
// unix 是「開一對 master/slave，把 slave 塞進子行程的 fd 0/1/2」。Windows 沒有
// 那個東西：這裡是先開兩條匿名管線，把它們交給 `CreatePseudoConsole` 換到一個
// **偽主控台代號**（HPCON），然後在建立行程的時候用一個
// `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` 屬性把那個代號綁上去。子行程於是以為
// 自己跑在一個真的主控台上（cmd、PowerShell、vim、甚至 `cls` 都會正常），而
// 我們兩端拿到的仍然是原始位元組。
//
// # 為什麼不用 os/exec
//
// `exec.Cmd` 送不出 STARTUPINFOEX 的屬性清單，而那正是綁 HPCON 的唯一方法。
// 所以這裡自己叫 `CreateProcessW`。用的是 `syscall.NewLazyDLL`（標準函式庫），
// **不是 cgo** —— kernel32 在每個行程裡本來就載入了，LazyDLL 拿到的是同一份。
//
// # 沒有訊號這種東西
//
// SIGHUP ＝ 把偽主控台關掉（「話筒掛了」本來就是這個字的意思，而且 ConPTY 會
// 讓接在上面的程式收到主控台關閉）。SIGTERM／SIGKILL ＝ `taskkill /T /F`，
// 連同它的子孫一起收 —— Windows 上沒有 process group 可以送訊號，job object
// 又太重（runner 的 kill_windows.go 是同一個結論）。
//
// # 誠實話
//
// 這個檔案是**照著 Microsoft 的 ConPTY 範例寫的、而且只做過交叉編譯驗證**：
// 這台開發機沒有 Windows，所以沒有人在真的 Windows 上跑過它。要接線之前請先
// 在一台 Windows 上手動開一次 cmd.exe、按一次 Ctrl-C、改一次視窗大小。
var (
	kernel32                          = syscall.NewLazyDLL("kernel32.dll")
	procCreatePseudoConsole           = kernel32.NewProc("CreatePseudoConsole")
	procResizePseudoConsole           = kernel32.NewProc("ResizePseudoConsole")
	procClosePseudoConsole            = kernel32.NewProc("ClosePseudoConsole")
	procInitializeProcThreadAttrList  = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute     = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList = kernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateProcessW                = kernel32.NewProc("CreateProcessW")
)

const (
	procThreadAttributePseudoConsole = 0x00020016
	extendedStartupInfoPresent       = 0x00080000
	createUnicodeEnvironment         = 0x00000400
)

// startupInfoEx 是 STARTUPINFOEX：一個 STARTUPINFO 後面接一個屬性清單指標。
type startupInfoEx struct {
	syscall.StartupInfo
	attributeList uintptr
}

type conptyBackend struct{}

// newPlatformBackend 檢查這台 Windows 有沒有 ConPTY。
//
// ConPTY 是 Windows 10 1809（build 17763）才有的。更舊的機器上
// `CreatePseudoConsole` 這個符號根本不存在，所以這裡就問得出來 —— 而且要在
// 開終端機**之前**問，答案才會變成「這台電腦太舊」而不是一個 0x7f 的錯誤碼。
func newPlatformBackend() (Backend, error) {
	if err := procCreatePseudoConsole.Find(); err != nil {
		return nil, errf(CodeUnsupported, "這台 Windows 太舊了：互動式終端機需要 Windows 10 1809 以上的 ConPTY。")
	}
	return conptyBackend{}, nil
}

func (conptyBackend) Name() string { return "conpty" }

func (conptyBackend) Open(spec Spec) (Handle, error) {
	if len(spec.Argv) == 0 {
		return nil, errf(CodeBadRequest, "沒有指定要跑哪一個程式")
	}

	// 兩條管線：inRead/outWrite 交給偽主控台，inWrite/outRead 留給我們。
	var inRead, inWrite, outRead, outWrite syscall.Handle
	if err := syscall.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, errf(CodeOpenFailed, "開不了輸入管線：%v", err)
	}
	if err := syscall.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		syscall.Close(inRead)
		syscall.Close(inWrite)
		return nil, errf(CodeOpenFailed, "開不了輸出管線：%v", err)
	}

	var hpc syscall.Handle
	hr, _, _ := procCreatePseudoConsole.Call(
		uintptr(coord(spec.Cols, spec.Rows)),
		uintptr(inRead), uintptr(outWrite), 0,
		uintptr(unsafe.Pointer(&hpc)),
	)
	// 這幾支回的是 HRESULT，不是 BOOL：0 才是成功，而且 GetLastError 不算數。
	if hr != 0 {
		syscall.Close(inRead)
		syscall.Close(inWrite)
		syscall.Close(outRead)
		syscall.Close(outWrite)
		return nil, errf(CodeOpenFailed, "CreatePseudoConsole 失敗（HRESULT 0x%x）", hr)
	}
	// 偽主控台已經複製了它要的那一份，我們這邊的副本要放掉 —— 不放的話
	// shell 結束時 outRead 讀不到結束。
	syscall.Close(inRead)
	syscall.Close(outWrite)

	pid, proc, err := startWithConsole(spec, hpc)
	if err != nil {
		procClosePseudoConsole.Call(uintptr(hpc))
		syscall.Close(inWrite)
		syscall.Close(outRead)
		return nil, err
	}

	return &conpty{
		hpc:  hpc,
		in:   os.NewFile(uintptr(inWrite), "conpty-in"),
		out:  os.NewFile(uintptr(outRead), "conpty-out"),
		pid:  pid,
		proc: proc,
		done: make(chan struct{}),
	}, nil
}

// startWithConsole 是「用 STARTUPINFOEX 建立一個綁在偽主控台上的行程」。
func startWithConsole(spec Spec, hpc syscall.Handle) (int, syscall.Handle, error) {
	// 屬性清單要先問長度再配空間；第一次呼叫**一定會失敗**
	// （ERROR_INSUFFICIENT_BUFFER），那是它回報長度的方式。
	var size uintptr
	procInitializeProcThreadAttrList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return 0, 0, errf(CodeSpawnFailed, "InitializeProcThreadAttributeList 問不出長度")
	}
	buf := make([]byte, size)
	list := uintptr(unsafe.Pointer(&buf[0]))
	if ok, _, e := procInitializeProcThreadAttrList.Call(list, 1, 0, uintptr(unsafe.Pointer(&size))); ok == 0 {
		return 0, 0, errf(CodeSpawnFailed, "InitializeProcThreadAttributeList 失敗：%v", e)
	}
	defer procDeleteProcThreadAttributeList.Call(list)

	if ok, _, e := procUpdateProcThreadAttribute.Call(
		list, 0, procThreadAttributePseudoConsole,
		uintptr(unsafe.Pointer(&hpc)), unsafe.Sizeof(hpc), 0, 0,
	); ok == 0 {
		return 0, 0, errf(CodeSpawnFailed, "UpdateProcThreadAttribute 失敗：%v", e)
	}

	si := startupInfoEx{attributeList: list}
	si.Cb = uint32(unsafe.Sizeof(si))

	appName, err := syscall.UTF16PtrFromString(spec.Argv[0])
	if err != nil {
		return 0, 0, errf(CodeBadRequest, "程式路徑不是合法的字串：%v", err)
	}
	cmdLine, err := syscall.UTF16PtrFromString(commandLine(spec.Argv))
	if err != nil {
		return 0, 0, errf(CodeBadRequest, "命令列不是合法的字串：%v", err)
	}
	var dir *uint16
	if spec.Cwd != "" {
		if dir, err = syscall.UTF16PtrFromString(spec.Cwd); err != nil {
			return 0, 0, errf(CodeBadRequest, "工作目錄不是合法的字串：%v", err)
		}
	}
	env, err := environmentBlock(spec.Env)
	if err != nil {
		return 0, 0, errf(CodeBadRequest, "環境變數不是合法的字串：%v", err)
	}

	var pi syscall.ProcessInformation
	ok, _, e := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0,
		0, // bInheritHandles=FALSE：偽主控台自己複製過它要的代號了
		uintptr(extendedStartupInfoPresent|createUnicodeEnvironment),
		uintptr(unsafe.Pointer(env)),
		uintptr(unsafe.Pointer(dir)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	// buf 一路活到 CreateProcessW 回來為止：它是屬性清單的實體，被 GC 掉的話
	// 這裡讀到的是別人的記憶體。
	runtime.KeepAlive(buf)
	// 這幾個是 Go 配置的記憶體，而它們是以 uintptr 的樣子傳進去的 —— 編譯器
	// 看不出它們還被用著。少了這幾行，GC 有權在 CreateProcessW 還在讀的時候
	// 就把它們回收掉。
	runtime.KeepAlive(appName)
	runtime.KeepAlive(cmdLine)
	runtime.KeepAlive(dir)
	runtime.KeepAlive(env)
	runtime.KeepAlive(&si)
	if ok == 0 {
		return 0, 0, errf(CodeSpawnFailed, "起不了 %s：%v", spec.Argv[0], e)
	}
	syscall.Close(pi.Thread)
	return int(pi.ProcessId), pi.Process, nil
}

type conpty struct {
	hpc  syscall.Handle
	in   *os.File
	out  *os.File
	pid  int
	proc syscall.Handle

	closeOnce sync.Once
	waitOnce  sync.Once
	done      chan struct{}
	exitCode  int
	waitErr   error
}

func (p *conpty) Pid() int { return p.pid }

func (p *conpty) Read(b []byte) (int, error) {
	n, err := p.out.Read(b)
	if err != nil && isEndWindows(err) {
		err = io.EOF
	}
	return n, err
}

func (p *conpty) Write(b []byte) (int, error) {
	n, err := p.in.Write(b)
	if err != nil && isEndWindows(err) {
		return n, io.EOF
	}
	return n, err
}

// isEndWindows：管線的另一端沒了。ERROR_BROKEN_PIPE(109) 與
// ERROR_NO_DATA(232) 都代表終端機結束，不是要回報給使用者的故障。
func isEndWindows(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ERROR_BROKEN_PIPE || errno == 232
	}
	return false
}

func (p *conpty) Resize(cols, rows int) error {
	hr, _, _ := procResizePseudoConsole.Call(uintptr(p.hpc), uintptr(coord(cols, rows)))
	if hr != 0 {
		return fmt.Errorf("ResizePseudoConsole 失敗（HRESULT 0x%x）", hr)
	}
	return nil
}

func (p *conpty) SignalGroup(sig GroupSignal) error {
	if sig == SignalHup {
		// 掛話筒：關掉偽主控台。接在上面的程式會看到主控台關閉，
		// 而我們這側的 Read 會拿到結束。
		procClosePseudoConsole.Call(uintptr(p.hpc))
		return nil
	}
	// /T 連子孫一起收。Windows 上沒有「對一個 group 送訊號」這回事，
	// 而 taskkill 是實務上最可靠的做法（runner/kill_windows.go 同一個結論）。
	return exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(p.pid)).Run()
}

func (p *conpty) Wait() (int, error) {
	p.waitOnce.Do(func() {
		if _, err := syscall.WaitForSingleObject(p.proc, syscall.INFINITE); err != nil {
			p.exitCode, p.waitErr = -1, err
			close(p.done)
			return
		}
		var code uint32
		if err := syscall.GetExitCodeProcess(p.proc, &code); err != nil {
			p.exitCode, p.waitErr = -1, err
		} else {
			p.exitCode = int(code)
		}
		close(p.done)
	})
	<-p.done
	return p.exitCode, p.waitErr
}

func (p *conpty) Close() error {
	p.closeOnce.Do(func() {
		// 先關偽主控台再關管線：反過來的話，還卡在 ReadFile 的那個 goroutine
		// 要等到寫入端被別人關掉才醒得過來。
		procClosePseudoConsole.Call(uintptr(p.hpc))
		_ = p.in.Close()
		_ = p.out.Close()
		syscall.Close(p.proc)
	})
	return nil
}

// coord 把 (cols, rows) 打包成一個 COORD：X 在低位、Y 在高位。
func coord(cols, rows int) uint32 {
	return uint32(uint16(cols)) | uint32(uint16(rows))<<16
}

// commandLine 照 Windows 的規矩把 argv 併成一行。
func commandLine(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

// environmentBlock 做出 CreateProcessW 要的那塊 UTF-16 環境區塊
// （KEY=VALUE\0KEY=VALUE\0\0）。空的就回 nil ＝ 沿用這個行程自己的環境。
//
// 排序是 Windows 自己的要求（Unicode 環境區塊要照大小寫不敏感的順序排）。
func environmentBlock(env map[string]string) (*uint16, error) {
	if len(env) == 0 {
		return nil, nil
	}
	entries := make([]string, 0, len(env))
	for k, v := range env {
		entries = append(entries, k+"="+v)
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToUpper(entries[i]) < strings.ToUpper(entries[j])
	})
	var block []uint16
	for _, e := range entries {
		u, err := syscall.UTF16FromString(e)
		if err != nil {
			return nil, err
		}
		block = append(block, u...) // UTF16FromString 已經帶了結尾的 NUL
	}
	block = append(block, 0) // 整塊再一個 NUL
	return &block[0], nil
}
