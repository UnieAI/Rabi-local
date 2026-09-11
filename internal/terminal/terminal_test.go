package terminal

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

/* ------------------------------------------------------------------ *
 * 一個假的 PTY，讓生命週期可以在沒有真終端機的機器上被測到
 * ------------------------------------------------------------------ */

type fakePty struct {
	mu      sync.Mutex
	written bytes.Buffer
	signals []GroupSignal
	sizes   [][2]int

	out      *io.PipeReader
	outWrite *io.PipeWriter
	exit     chan int
	waitOnce sync.Once
	code     int
	done     chan struct{}
	closed   chan struct{}
}

type fakeBackend struct {
	mu   sync.Mutex
	last *fakePty
	spec Spec
	err  error
}

func (b *fakeBackend) Name() string { return "fake" }

func (b *fakeBackend) Open(spec Spec) (Handle, error) {
	if b.err != nil {
		return nil, b.err
	}
	r, w := io.Pipe()
	p := &fakePty{out: r, outWrite: w, exit: make(chan int, 1), done: make(chan struct{}), closed: make(chan struct{})}
	b.mu.Lock()
	b.last, b.spec = p, spec
	b.mu.Unlock()
	return p, nil
}

func (b *fakeBackend) pty() *fakePty {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}

func (p *fakePty) Pid() int { return 4242 }

func (p *fakePty) Read(b []byte) (int, error) {
	n, err := p.out.Read(b)
	if err != nil {
		return n, io.EOF
	}
	return n, nil
}

func (p *fakePty) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.written.Write(b)
}

func (p *fakePty) Resize(cols, rows int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sizes = append(p.sizes, [2]int{cols, rows})
	return nil
}

func (p *fakePty) SignalGroup(sig GroupSignal) error {
	p.mu.Lock()
	p.signals = append(p.signals, sig)
	p.mu.Unlock()
	if sig == SignalHup || sig == SignalKill {
		p.finish(129)
	}
	return nil
}

func (p *fakePty) Wait() (int, error) {
	p.waitOnce.Do(func() {
		p.code = <-p.exit
		close(p.done)
	})
	<-p.done
	return p.code, nil
}

func (p *fakePty) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
		_ = p.out.Close()
	}
	return nil
}

// finish 模擬 shell 結束。
func (p *fakePty) finish(code int) {
	select {
	case p.exit <- code:
	default:
	}
}

// say 模擬終端機吐出一段輸出。
func (p *fakePty) say(s string) {
	_, _ = p.outWrite.Write([]byte(s))
}

func (p *fakePty) typed() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.written.String()
}

func (p *fakePty) sentSignals() []GroupSignal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]GroupSignal(nil), p.signals...)
}

/* ------------------------------------------------------------------ *
 * 測試用的腳手架
 * ------------------------------------------------------------------ */

// collector 收事件，並且讓測試等某一種事件出現。
type collector struct {
	mu     sync.Mutex
	events []Event
	ch     chan Event
}

func newCollector() *collector { return &collector{ch: make(chan Event, 64)} }

func (c *collector) emit(e Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
	c.ch <- e
}

func (c *collector) wait(t *testing.T, kind string) Event {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case e := <-c.ch:
			if e.Event == kind {
				return e
			}
		case <-deadline:
			t.Fatalf("等不到 %s 事件；目前收到 %v", kind, c.kinds())
		}
	}
}

func (c *collector) kinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.events))
	for _, e := range c.events {
		out = append(out, e.Event)
	}
	return out
}

// newTestService 是一個接了假 PTY、假 shell、而且票一律通過的 Service。
func newTestService(t *testing.T) (*Service, *fakeBackend, string) {
	t.Helper()
	root := t.TempDir()
	backend := &fakeBackend{}
	svc := New(Options{
		Root:     root,
		Contain:  fixedScope{root},
		Approval: GateFunc(func(_, _, _ string) (string, error) { return "action", nil }),
		Backend:  backend,
		Env:      []string{"SHELL=/bin/sh", "USER=roy", "OPENAI_API_KEY=sk-secret"},
		Hostname: func() string { return "roy-mbp.local" },
		LookPath: testLookPath,
	})
	return svc, backend, root
}

// fixedScope 是 runner.Scope 的最小替身：只准 root 底下的路徑。
type fixedScope struct{ root string }

func (s fixedScope) Resolve(p string) (string, error) {
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(s.root, p)
	}
	abs = filepath.Clean(abs)
	if abs != s.root && !bytes.HasPrefix([]byte(abs), []byte(s.root+string(os.PathSeparator))) {
		return "", errors.New("outside")
	}
	return abs, nil
}

/* ------------------------------------------------------------------ *
 * 測試
 * ------------------------------------------------------------------ */

func TestOpenEmitsOpenedThenDataThenExit(t *testing.T) {
	svc, backend, root := newTestService(t)
	c := newCollector()

	view, err := svc.Open(OpenRequest{TerminalID: "t1", Cols: 120, Rows: 40, Approval: "ticket"}, c.emit)
	if err != nil {
		t.Fatalf("開不起來：%v", err)
	}
	if view.Cwd != root {
		t.Errorf("沒有指定 cwd 的話應該從授權資料夾開始，得到 %q", view.Cwd)
	}
	if view.Title != "roy@roy-mbp" {
		t.Errorf("分頁標題應該是 user@host（去掉網域），得到 %q", view.Title)
	}
	if view.Shell != testShell() {
		t.Errorf("shell 應該是 $SHELL，得到 %q", view.Shell)
	}

	opened := c.wait(t, "opened")
	if opened.PID != 4242 || opened.Cols != 120 || opened.Rows != 40 {
		t.Errorf("opened 帶錯東西：%+v", opened)
	}

	// shell 不可以帶旗標（見套件說明）。
	backend.mu.Lock()
	argv := backend.spec.Argv
	env := backend.spec.Env
	backend.mu.Unlock()
	if len(argv) != 1 || argv[0] != testShell() {
		t.Errorf("shell 不該帶任何旗標，得到 %v", argv)
	}
	if env["TERM"] != "xterm-256color" || env["COLORTERM"] != "truecolor" {
		t.Errorf("TERM/COLORTERM 沒有設好：%v", env)
	}
	if _, leaked := env["OPENAI_API_KEY"]; leaked {
		t.Error("provider 金鑰漏進終端機了 —— 白名單沒有生效")
	}
	if env["PWD"] != root {
		t.Errorf("PWD 應該是起始資料夾，得到 %q", env["PWD"])
	}

	backend.pty().say("hello\r\n")
	data := c.wait(t, "data")
	if string(data.Data) != "hello\r\n" {
		t.Errorf("輸出被動過：%q", data.Data)
	}

	backend.pty().finish(3)
	exit := c.wait(t, "exit")
	if exit.ExitCode == nil || *exit.ExitCode != 3 {
		t.Errorf("離開碼不對：%+v", exit)
	}
	if exit.ClosedByClient {
		t.Error("shell 自己結束的，不該說是客戶端關的")
	}
}

func TestReplayAndAttachSurviveAReconnect(t *testing.T) {
	svc, backend, _ := newTestService(t)
	first := newCollector()
	if _, err := svc.Open(OpenRequest{TerminalID: "t1", Approval: "ticket"}, first.emit); err != nil {
		t.Fatal(err)
	}
	first.wait(t, "opened")
	backend.pty().say("before\r\n")
	first.wait(t, "data")

	// 瀏覽器重新整理：換一個收事件的人，先把留著的輸出畫回來。
	second := newCollector()
	view, scroll, err := svc.Attach("t1", second.emit)
	if err != nil {
		t.Fatalf("接不回來：%v", err)
	}
	if !view.Live {
		t.Error("shell 還在跑，view 應該是 live")
	}
	if string(scroll) != "before\r\n" {
		t.Errorf("replay 的內容不對：%q", scroll)
	}

	backend.pty().say("after\r\n")
	got := second.wait(t, "data")
	if string(got.Data) != "after\r\n" {
		t.Errorf("新的一側沒有收到之後的輸出：%q", got.Data)
	}

	replay, err := svc.Replay("t1")
	if err != nil {
		t.Fatal(err)
	}
	if string(replay) != "before\r\nafter\r\n" {
		t.Errorf("捲動內容不完整：%q", replay)
	}
}

func TestCloseProducesExactlyOneEndingMarkedByClient(t *testing.T) {
	svc, backend, _ := newTestService(t)
	c := newCollector()
	if _, err := svc.Open(OpenRequest{TerminalID: "t1", Approval: "ticket"}, c.emit); err != nil {
		t.Fatal(err)
	}
	c.wait(t, "opened")

	if !svc.Close("t1") {
		t.Fatal("Close 應該回 true")
	}
	exit := c.wait(t, "exit")
	if !exit.ClosedByClient {
		t.Error("是客戶端關的，exit 要說出來")
	}
	if sigs := backend.pty().sentSignals(); len(sigs) == 0 || sigs[0] != SignalHup {
		t.Errorf("關閉應該先送 SIGHUP，得到 %v", sigs)
	}

	// 再關一次不該再產生一個結束。
	svc.Close("t1")
	time.Sleep(50 * time.Millisecond)
	count := 0
	for _, k := range c.kinds() {
		if k == "exit" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("一次關閉只能有一個結束，得到 %d 個", count)
	}
}

func TestInterruptKeysAreBytesNotKills(t *testing.T) {
	svc, backend, _ := newTestService(t)
	c := newCollector()
	if _, err := svc.Open(OpenRequest{TerminalID: "t1", Approval: "ticket"}, c.emit); err != nil {
		t.Fatal(err)
	}
	c.wait(t, "opened")

	for _, tc := range []struct {
		signal string
		want   byte
	}{{"SIGINT", 0x03}, {"SIGQUIT", 0x1c}, {"SIGTSTP", 0x1a}} {
		delivered, err := svc.Signal("t1", tc.signal)
		if err != nil {
			t.Fatalf("%s：%v", tc.signal, err)
		}
		if delivered != "key" {
			t.Errorf("%s 應該以按鍵送出，得到 %q", tc.signal, delivered)
		}
	}
	if got := backend.pty().typed(); got != "\x03\x1c\x1a" {
		t.Errorf("送出去的位元組不對：%q", got)
	}
	if sigs := backend.pty().sentSignals(); len(sigs) != 0 {
		t.Errorf("中斷鍵不可以變成訊號，得到 %v", sigs)
	}

	delivered, err := svc.Signal("t1", "SIGTERM")
	if err != nil || delivered != "group" {
		t.Errorf("SIGTERM 應該打整個 process group，得到 %q / %v", delivered, err)
	}
	if _, err := svc.Signal("t1", "SIGUSR1"); CodeOf(err) != CodeBadRequest {
		t.Errorf("沒有鍵也不在清單裡的訊號應該被擋下來，得到 %v", err)
	}
}

func TestInputAndResize(t *testing.T) {
	svc, backend, _ := newTestService(t)
	c := newCollector()
	if _, err := svc.Open(OpenRequest{TerminalID: "t1", Cols: 80, Rows: 24, Approval: "ticket"}, c.emit); err != nil {
		t.Fatal(err)
	}
	c.wait(t, "opened")

	if n, err := svc.Input("t1", []byte("ls\n")); err != nil || n != 3 {
		t.Fatalf("Input：%d / %v", n, err)
	}
	if got := backend.pty().typed(); got != "ls\n" {
		t.Errorf("按鍵被改過：%q（不可以自己加東西，連換行都不行）", got)
	}

	// 版面在掛載中量到 0 —— 夾住，不是拒絕。
	view, err := svc.Resize("t1", 0, 0)
	if err != nil {
		t.Fatalf("Resize 不該失敗：%v", err)
	}
	if view.Cols != 80 || view.Rows != 24 {
		t.Errorf("0 應該退回原本的大小，得到 %dx%d", view.Cols, view.Rows)
	}
	view, _ = svc.Resize("t1", 99999, 50)
	if view.Cols != 1000 || view.Rows != 50 {
		t.Errorf("太大的值要夾到 1000，得到 %dx%d", view.Cols, view.Rows)
	}
}

func TestOpenRefusesWithoutApprovalAndOutsideRoot(t *testing.T) {
	root := t.TempDir()
	backend := &fakeBackend{}
	svc := New(Options{
		Root:     root,
		Contain:  fixedScope{root},
		Approval: GateFunc(func(_, _, _ string) (string, error) { return "", errors.New("expired") }),
		Backend:  backend,
		Env:      []string{"SHELL=/bin/sh"},
		LookPath: testLookPath,
	})

	if _, err := svc.Open(OpenRequest{TerminalID: "t1", Approval: "stale"}, func(Event) {}); CodeOf(err) != CodeApprovalBad {
		t.Errorf("票被拒絕應該回 %s，得到 %v", CodeApprovalBad, err)
	}
	if backend.pty() != nil {
		t.Fatal("票沒過就不該開出 PTY")
	}

	// 越界要在**問使用者之前**就擋下來。
	svc2 := New(Options{
		Root:    root,
		Contain: fixedScope{root},
		Approval: GateFunc(func(_, _, _ string) (string, error) {
			t.Fatal("越界的路徑不該送去問使用者")
			return "", nil
		}),
		Backend:  backend,
		Env:      []string{"SHELL=/bin/sh"},
		LookPath: testLookPath,
	})
	// outsideDir() 而不是寫死 /etc —— 在 Windows 上 /etc 不是絕對路徑，
	// 會被接到授權資料夾後面變成一個合法的路徑（見 shell_fixture_test.go）。
	if _, err := svc2.Open(OpenRequest{TerminalID: "t2", Cwd: outsideDir(), Approval: "ok"}, func(Event) {}); CodeOf(err) != CodeOutsideRoot {
		t.Errorf("越界應該回 %s，得到 %v", CodeOutsideRoot, err)
	}
}

func TestTooManyTerminals(t *testing.T) {
	svc, _, _ := newTestService(t)
	svc.opts.MaxTerminals = 2
	for _, id := range []string{"a", "b"} {
		if _, err := svc.Open(OpenRequest{TerminalID: id, Approval: "ticket"}, func(Event) {}); err != nil {
			t.Fatalf("%s 開不起來：%v", id, err)
		}
	}
	if _, err := svc.Open(OpenRequest{TerminalID: "c", Approval: "ticket"}, func(Event) {}); CodeOf(err) != CodeTooMany {
		t.Errorf("第三個應該回 %s，得到 %v", CodeTooMany, err)
	}
}

func TestOperationsOnGoneOrExitedTerminal(t *testing.T) {
	svc, backend, _ := newTestService(t)
	c := newCollector()
	if _, err := svc.Open(OpenRequest{TerminalID: "t1", Approval: "ticket"}, c.emit); err != nil {
		t.Fatal(err)
	}
	c.wait(t, "opened")

	if _, err := svc.Input("nope", []byte("x")); CodeOf(err) != CodeNoTerminal {
		t.Errorf("不存在的終端機應該回 %s，得到 %v", CodeNoTerminal, err)
	}

	backend.pty().finish(0)
	c.wait(t, "exit")
	if _, err := svc.Input("t1", []byte("x")); CodeOf(err) != CodeExited {
		t.Errorf("已經結束的終端機應該回 %s，得到 %v", CodeExited, err)
	}
	// 結束之後捲動內容還要讀得到 —— 面板上那一格不會突然變空白。
	if _, err := svc.Replay("t1"); err != nil {
		t.Errorf("結束之後還要能 replay，得到 %v", err)
	}
}

func TestDispatchWireShapes(t *testing.T) {
	svc, backend, _ := newTestService(t)

	var partials []map[string]any
	var mu sync.Mutex
	done := make(chan Result, 1)
	go func() {
		done <- svc.Dispatch(Frame{
			ID: "invoke-1", Op: "terminalOpen",
			Args:     map[string]any{"cols": float64(100), "rows": float64(30)},
			Approval: "ticket",
		}, func(p map[string]any) {
			mu.Lock()
			partials = append(partials, p)
			mu.Unlock()
		})
	}()

	// 等 PTY 真的開出來。
	deadline := time.Now().Add(2 * time.Second)
	for backend.pty() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if backend.pty() == nil {
		t.Fatal("terminalOpen 沒有開出 PTY")
	}

	// 沒有給 terminalId 的話，**invoke id 就是終端機的名字**。
	if _, err := svc.Replay("invoke-1"); err != nil {
		t.Fatalf("invoke id 應該就是 terminalId：%v", err)
	}

	backend.pty().say("hi")
	time.Sleep(50 * time.Millisecond)

	// 後續呼叫用 args.id 指名同一個終端機。
	res := svc.Dispatch(Frame{Op: "terminalInput", Args: map[string]any{"id": "invoke-1", "dataBase64": "bHM="}}, nil)
	if !res.OK || res.Output["bytes"] != 2 {
		t.Errorf("terminalInput 回的東西不對：%+v", res)
	}
	if got := backend.pty().typed(); got != "ls" {
		t.Errorf("base64 沒有被解開：%q", got)
	}

	backend.pty().finish(7)
	final := <-done
	if !final.OK {
		t.Fatalf("terminalOpen 應該以成功收尾：%+v", final)
	}
	exit, ok := final.Output["exit"].(map[string]any)
	if !ok {
		t.Fatalf("最後的結果要有 output.exit：%+v", final.Output)
	}
	if code, ok := exit["code"].(*int); !ok || *code != 7 {
		t.Errorf("離開碼不對：%+v", exit)
	}

	mu.Lock()
	defer mu.Unlock()
	var sawOpened, sawData bool
	for _, p := range partials {
		if s, ok := p["dataBase64"].(string); ok && s == "aGk=" {
			sawData = true
		}
		if term, ok := p["terminal"].(map[string]any); ok && term["event"] == "opened" {
			sawOpened = true
		}
		if _, isExit := p["exit"]; isExit {
			t.Error("exit 不可以同時當 partial 送")
		}
	}
	if !sawOpened {
		t.Error("opened 應該包在 {terminal: …} 裡送出去")
	}
	if !sawData {
		t.Errorf("輸出應該是最上層的 dataBase64，收到 %v", partials)
	}
}

func TestCloseAllEndsEveryTerminal(t *testing.T) {
	svc, backend, _ := newTestService(t)
	c := newCollector()
	if _, err := svc.Open(OpenRequest{TerminalID: "t1", Approval: "ticket"}, c.emit); err != nil {
		t.Fatal(err)
	}
	c.wait(t, "opened")

	svc.CloseAll()
	c.wait(t, "exit")
	if len(svc.List()) != 0 {
		t.Errorf("CloseAll 之後登記簿應該是空的，得到 %v", svc.List())
	}
	if sigs := backend.pty().sentSignals(); len(sigs) == 0 {
		t.Error("CloseAll 要真的去殺那個 shell —— 活過 daemon 的 shell 沒有人叫得動")
	}
}

func TestDisabledService(t *testing.T) {
	svc := New(Options{Root: t.TempDir(), Disabled: true})
	if svc.Available() {
		t.Error("關掉的服務不該說自己可用")
	}
	if len(svc.Ops()) != 0 {
		t.Error("開不了終端機的機器不該宣傳 terminal* 的 op")
	}
	if _, err := svc.Open(OpenRequest{TerminalID: "t1"}, func(Event) {}); CodeOf(err) != CodeDisabled {
		t.Errorf("應該回 %s，得到 %v", CodeDisabled, err)
	}
}

// TestOpenAgainReattachesInsteadOfFailing —— 雲端重連之後會用同一個 terminalId
// 再開一次。那不是錯誤，是「把線接回同一個 shell」。
func TestOpenAgainReattachesInsteadOfFailing(t *testing.T) {
	svc, backend, root := newTestService(t)
	first := newCollector()
	if _, err := svc.Open(OpenRequest{TerminalID: "t1", Approval: "ticket"}, first.emit); err != nil {
		t.Fatal(err)
	}
	first.wait(t, "opened")
	firstPty := backend.pty()

	second := newCollector()
	view, err := svc.Open(OpenRequest{TerminalID: "t1", Approval: "ticket"}, second.emit)
	if err != nil {
		t.Fatalf("重開同一個 id 應該是重新接上：%v", err)
	}
	if backend.pty() != firstPty {
		t.Fatal("重新接上不可以開出第二個 shell")
	}
	// 新的一側要拿得到 pid／起始資料夾／標題，不然它畫不出那個分頁。
	opened := second.wait(t, "opened")
	if opened.PID != view.PID || opened.Cwd != root {
		t.Errorf("重新接上時的 opened 帶錯東西：%+v", opened)
	}

	backend.pty().say("after-reconnect")
	got := second.wait(t, "data")
	if string(got.Data) != "after-reconnect" {
		t.Errorf("新的一側沒有接到輸出：%q", got.Data)
	}

	// 同一個名字、不同的起點，是兩件事。
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Open(OpenRequest{TerminalID: "t1", Cwd: sub, Approval: "ticket"}, func(Event) {}); CodeOf(err) != CodeExists {
		t.Errorf("起點不一樣應該回 %s，得到 %v", CodeExists, err)
	}
}
