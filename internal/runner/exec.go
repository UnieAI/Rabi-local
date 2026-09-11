package runner

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// ExecRequest 是雲端送下來的一次指令。
//
// 注意這裡拿到的是**結構化**的欄位（command / args / env / cwd），不是一串已經
// 拼好的 shell 字串。SSH 後端非得拼字串不可（它只能送一行字給遠端 shell），
// 這裡不必 —— 少一層拼接就少一整類跳脫的錯。
type ExecRequest struct {
	ID      string            `json:"id"`
	Kind    string            `json:"kind"` // bash | python | raw
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	Cwd     string            `json:"cwd"`
	Stdin   string            `json:"stdin"` // base64

	// FullEnv 整份**取代**子行程的環境，而不是疊在 os.Environ() 上面。
	//
	// **允許清單必須能讓一個變數「不存在」，不只是「值是空的」。** 疊加的作法
	// 只蓋得住值：`OPENAI_API_KEY=` 仍然出現在 environ 裡，任何一個「有設就
	// 用」的程式都會拿它當真，而 `env | grep` 看起來也像祕密還在。
	//
	// nil ＝ 照舊（繼承 + 疊 Env）。呼叫端要用允許清單就把
	// `envguard.ChildEnvFromOS(...)` 的結果放進來（見 internal/envguard）。
	FullEnv []string `json:"-"`
}

// ExecEvents 是執行過程要回報給雲端的三種事件。
type ExecEvents struct {
	Stdout func(id string, chunk []byte)
	Stderr func(id string, chunk []byte)
	Exit   func(id string, code int, signal string, errMsg string)
}

// Runner 管理所有正在跑的指令，並且知道怎麼把它們整棵殺掉。
type Runner struct {
	mu      sync.Mutex
	running map[string]*process
	events  ExecEvents
}

type process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	cancel context.CancelFunc
}

func New(events ExecEvents) *Runner {
	return &Runner{running: map[string]*process{}, events: events}
}

// shellFor 決定用什麼跑一段 bash 指令。
//
// agent 送下來的一律是 bash 語法。Unix 上就是 bash。Windows 上沒有 bash，
// 除非裝了 WSL —— 找得到就用它（語法才對得上），找不到就退回 PowerShell 並
// 讓指令自己去失敗，而不是在這裡假裝成功。
func shellFor(kind string) (string, []string, bool) {
	switch kind {
	case "python":
		if p, err := exec.LookPath("python3"); err == nil {
			return p, []string{"-c"}, true
		}
		if p, err := exec.LookPath("python"); err == nil {
			return p, []string{"-c"}, true
		}
		return "", nil, false
	default: // bash / 其他
		if p, err := exec.LookPath("bash"); err == nil {
			return p, []string{"-lc"}, true
		}
		if runtime.GOOS == "windows" {
			if p, err := exec.LookPath("powershell.exe"); err == nil {
				return p, []string{"-NoProfile", "-Command"}, true
			}
		}
		if p, err := exec.LookPath("sh"); err == nil {
			return p, []string{"-lc"}, true
		}
		return "", nil, false
	}
}

// Start 開始執行一個指令。它立刻回傳；輸出與結束都走 events 回報。
func (r *Runner) Start(scope *Scope, req ExecRequest) {
	fail := func(msg string) {
		if r.events.Exit != nil {
			r.events.Exit(req.ID, -1, "", msg)
		}
	}

	// 工作目錄一定要在授權範圍內 —— 這是 cwd，不是隨便一個參數，
	// 指令會從那裡開始看世界。
	cwd, err := scope.Resolve(req.Cwd)
	if err != nil {
		fail("工作目錄不在已授權的資料夾裡")
		return
	}
	if st, err := os.Stat(cwd); err != nil || !st.IsDir() {
		fail("工作目錄不存在")
		return
	}

	var bin string
	var pre []string
	var ok bool
	if req.Kind == "raw" {
		bin, ok = req.Command, req.Command != ""
		if !ok {
			fail("沒有指定要執行什麼")
			return
		}
	} else {
		bin, pre, ok = shellFor(req.Kind)
		if !ok {
			fail("這台電腦上找不到可以執行指令的 shell")
			return
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	var argv []string
	if req.Kind == "raw" {
		argv = req.Args
	} else {
		argv = append(append([]string{}, pre...), req.Command)
	}
	cmd := exec.CommandContext(ctx, bin, argv...)
	cmd.Dir = cwd
	if req.FullEnv != nil {
		// 整份取代 —— 不在清單上的變數**不存在**，不是值為空。
		cmd.Env = append([]string{}, req.FullEnv...)
	} else {
		cmd.Env = os.Environ()
	}
	for k, v := range req.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	setProcessGroup(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		fail(err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		fail(err.Error())
		return
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		fail(err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		cancel()
		fail(err.Error())
		return
	}

	r.mu.Lock()
	r.running[req.ID] = &process{cmd: cmd, stdin: stdin, cancel: cancel}
	r.mu.Unlock()

	if req.Stdin != "" {
		if raw, err := base64.StdEncoding.DecodeString(req.Stdin); err == nil {
			_, _ = stdin.Write(raw)
		}
	}
	// 沒有互動需求的指令要看到 EOF，否則 `cat` 之類的東西會永遠等下去。
	// 需要餵 stdin 的長駐行程是另一條路（還沒實作）。
	_ = stdin.Close()

	var wg sync.WaitGroup
	pump := func(rd io.Reader, emit func(string, []byte)) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := rd.Read(buf)
			if n > 0 && emit != nil {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				emit(req.ID, chunk)
			}
			if err != nil {
				return
			}
		}
	}
	wg.Add(2)
	go pump(stdout, r.events.Stdout)
	go pump(stderr, r.events.Stderr)

	go func() {
		wg.Wait() // 先把輸出讀乾淨，再回報結束 —— 否則最後幾行會遺失
		err := cmd.Wait()
		cancel()

		r.mu.Lock()
		delete(r.running, req.ID)
		r.mu.Unlock()

		code := 0
		msg := ""
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else {
				code = -1
				msg = err.Error()
			}
		}
		if r.events.Exit != nil {
			r.events.Exit(req.ID, code, "", msg)
		}
	}()
}

// Cancel 中止一個指令，連同它啟動的一切。
//
// 先 TERM 給它兩秒收尾，再 KILL —— 直接 KILL 會讓正在寫檔的工具留下半截檔案。
func (r *Runner) Cancel(id string) {
	r.mu.Lock()
	p := r.running[id]
	r.mu.Unlock()
	if p == nil || p.cmd.Process == nil {
		return
	}
	pid := p.cmd.Process.Pid
	_ = killTree(pid, termSignal())
	go func() {
		time.Sleep(2 * time.Second)
		r.mu.Lock()
		still := r.running[id]
		r.mu.Unlock()
		if still != nil {
			_ = killTree(pid, killSignal())
			still.cancel()
		}
	}()
}

// CancelAll 收掉所有還在跑的東西。使用者按「停止」或程式結束時呼叫 ——
// 不做的話那些行程會活過桌面程式，而且之後沒有人殺得掉它們。
func (r *Runner) CancelAll() {
	r.mu.Lock()
	ids := make([]string, 0, len(r.running))
	for id := range r.running {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		r.Cancel(id)
	}
}

// Running 回報目前有幾個指令在跑。工具列顯示用。
func (r *Runner) Running() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.running)
}
