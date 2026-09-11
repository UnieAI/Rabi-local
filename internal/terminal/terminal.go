package terminal

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Contain 把雲端送下來的路徑解析成這台電腦上的絕對路徑，並且確認它落在使用者
// 授權過的資料夾裡面。
//
// 刻意是一個**窄介面**而不是直接引用 runner.Scope：這個套件不需要知道授權是
// 怎麼存的，而 runner.Scope 的 Resolve 剛好就是這個形狀，接線的時候直接傳進來
// 即可（*runner.Scope 自動滿足這個介面）。
//
// 沒有給 Contain 的話，**任何帶 cwd 的開啟請求都會被拒絕**（只准從 Root 開）。
// 這是刻意的 fail-closed：一個「沒有人檢查路徑」的預設值，會在接線的人忘了那
// 一行的時候變成一個可以從任何資料夾開 shell 的洞。
type Contain interface {
	Resolve(path string) (string, error)
}

// View 是一個終端機現在的樣子。前端拿它畫分頁。
type View struct {
	TerminalID string `json:"terminalId"`
	// Cwd 是 shell **起始**的資料夾。它不會跟著 `cd` 變 —— 那是 shell 自己的事，
	// 而且一個終端機本來就可以走到使用者自己的帳號走得到的任何地方。
	Cwd   string `json:"cwd"`
	Shell string `json:"shell"`
	// Title 是分頁上的字：`user@host`，就像終端機模擬器替視窗取名那樣。
	Title string `json:"title"`
	Cols  int    `json:"cols"`
	Rows  int    `json:"rows"`
	PID   int    `json:"pid"`
	// Live 在 shell 結束之後變成 false，但捲動內容仍然讀得到。
	Live     bool `json:"live"`
	ExitCode *int `json:"exitCode,omitempty"`
}

// Event 是一個終端機講的話。四種，順序保證是 opened → (data|alive)* → exit。
type Event struct {
	// Event 是 "opened" / "data" / "alive" / "exit"。
	Event      string
	TerminalID string
	// Data 是 PTY 產生的**原始位元組**，這一層不解碼也不轉字串（見套件說明）。
	Data []byte
	// 以下只有 opened 會帶。
	PID   int
	Cwd   string
	Shell string
	Title string
	Cols  int
	Rows  int
	// 以下只有 exit 會帶。
	ExitCode       *int
	ClosedByClient bool
}

// Options 是建一個 Service 要的東西。除了 Root 以外都有合理的預設值。
type Options struct {
	// Root 是使用者授權的資料夾；沒有指定 cwd 的終端機從這裡開始。
	Root string
	// Contain 檢查 cwd（見上面的說明）。
	Contain Contain
	// Approval 驗核准票。**不給就是每一次開啟都拒絕**（fail-closed）。
	Approval ApprovalGate
	// Disabled ＝ 這個 build 不提供互動式終端機。零值是啟用。
	Disabled bool
	// MaxTerminals 是同時活著的上限，預設 4。
	MaxTerminals int
	// ScrollbackMaxBytes 是每個終端機保留多少輸出，預設 256 KiB。
	ScrollbackMaxBytes int
	// DisposeGrace 是關閉時給它好好死的時間，預設 3 秒。
	DisposeGrace time.Duration
	// KeepAlive 是閒置時多久證明一次自己還在，預設 5 分鐘。
	KeepAlive time.Duration
	// Backend 注入用（測試給一個假的 PTY）。不給就用這台機器上的。
	Backend Backend
	// Env 是這台電腦的環境變數來源，預設 os.Environ()。
	Env []string
	// Hostname 預設 os.Hostname。
	Hostname func() string
	// LookPath 判斷一個 shell 在不在，預設看檔案系統。注入用。
	LookPath func(path string) bool
	// Audit 寫稽核列。事後要看得出「這台電腦上開過哪些終端機、誰批的」。
	Audit func(op, detail, verdict, actionID string)
	Log   *log.Logger
}

// Service 是這台電腦上所有終端機工作階段的登記簿。
//
// # 生命週期：一個終端機活在 daemon 裡
//
// 它**不屬於**任何一輪對話、也不屬於任何一個 HTTP 請求。使用者換一個對話、
// 重新整理瀏覽器、甚至讓雲端那條連線斷掉再接回來，那個跑著 `npm run dev` 的
// shell 都還在 —— 接回來的方法是 Attach（換一個收事件的人）加 Replay（把留著的
// 輸出重畫一次）。它只有三種死法：shell 自己結束、使用者按關閉、daemon 停掉
// （CloseAll）。
//
// 最後一種是刻意的：一個活過 daemon 的 shell，是使用者之後**再也叫不動、
// 也殺不掉**的行程。
type Service struct {
	opts Options

	mu        sync.Mutex
	terminals map[string]*session

	backendOnce sync.Once
	backend     Backend
	backendErr  error
}

type session struct {
	svc *Service

	mu   sync.Mutex
	view View
	// emitMu 保證同一個終端機的事件一次只有一個人在送 —— 輸出來自泵的
	// goroutine、alive 來自計時器，收事件的那一側不該被迫自己處理併發。
	emitMu sync.Mutex
	emit   func(Event)

	handle         Handle
	scroll         *scrollback
	closedByClient bool
	settled        bool
	stopKeepAlive  chan struct{}
	pumpDone       chan struct{}
}

// New 建一個登記簿。
func New(opts Options) *Service {
	if opts.MaxTerminals <= 0 {
		opts.MaxTerminals = 4
	}
	if opts.ScrollbackMaxBytes <= 0 {
		opts.ScrollbackMaxBytes = 256 * 1024
	}
	if opts.DisposeGrace <= 0 {
		opts.DisposeGrace = 3 * time.Second
	}
	if opts.KeepAlive <= 0 {
		// 這是**保險，不是心跳**。雲端那側用「沉默多久」來判斷一個呼叫死了沒，
		// 而那個上限是以天計的，所以閒置的 shell 本來就活得下來。它存在是為了
		// 讓之後任何一個比較短的上限，不會把「使用者去讀了一份文件」靜靜地
		// 變成一個死掉的終端機。五分鐘遠低於任何合理的上限，一小時十二則。
		opts.KeepAlive = 5 * time.Minute
	}
	if opts.Env == nil {
		opts.Env = os.Environ()
	}
	if opts.Hostname == nil {
		opts.Hostname = func() string {
			h, err := os.Hostname()
			if err != nil {
				return ""
			}
			return h
		}
	}
	if opts.LookPath == nil {
		opts.LookPath = executableExists
	}
	if opts.Root != "" {
		if abs, err := filepath.Abs(opts.Root); err == nil {
			opts.Root = abs
		}
	}
	return &Service{opts: opts, terminals: map[string]*session{}}
}

// Available 回報這台機器現在開不開得了終端機。hello 的 posture 用它。
func (s *Service) Available() bool {
	if s.opts.Disabled {
		return false
	}
	_, err := s.resolveBackend()
	return err == nil
}

// Ops 是這個套件負責的那幾個 op。接線的人把它併進 hello 的能力清單。
//
// **一台開不了 PTY 的機器不該宣傳這些 op** —— 雲端看到的要是「這台機器開不了
// 終端機」這個事實，而不是一個會在使用者按下去之後才失敗的按鈕。
func (s *Service) Ops() []string {
	if !s.Available() {
		return nil
	}
	return []string{"terminalOpen", "terminalInput", "terminalResize", "terminalSignal", "terminalClose", "terminalReplay"}
}

func (s *Service) resolveBackend() (Backend, error) {
	s.backendOnce.Do(func() {
		if s.opts.Backend != nil {
			s.backend = s.opts.Backend
			return
		}
		s.backend, s.backendErr = DefaultBackend()
	})
	if s.backendErr != nil {
		return nil, s.backendErr
	}
	return s.backend, nil
}

func (s *Service) audit(op, detail, verdict, actionID string) {
	if s.opts.Audit != nil {
		s.opts.Audit(op, detail, verdict, actionID)
	}
}

func (s *Service) logf(format string, a ...any) {
	if s.opts.Log != nil {
		s.opts.Log.Printf(format, a...)
	}
}

// OpenRequest 是開一個終端機的請求。
type OpenRequest struct {
	// TerminalID 是這個終端機之後的名字。雲端用開啟那一次的 invoke id 當它。
	TerminalID string
	// Cwd 是雲端**原樣送下來**的字串。
	//
	// 注意：核准票綁的是這個字串，不是解析之後的絕對路徑（見 approval.go）。
	Cwd string
	// Env 是雲端要求額外塞進去的環境變數。正常路徑上不會有，但它**在票裡**，
	// 因為「有人想在這個 shell 裡種變數」正是核准卡要能誠實說出來的事。
	Env        map[string]string
	Cols, Rows int
	// Approval 是使用者按下允許之後簽出來的票。
	Approval string
}

// Open 開一個終端機。emit 會依序收到這個終端機講的每一句話，從 opened 開始。
//
// 同一個 TerminalID 再開一次、而且 cwd 一樣的話，這是**重新接上**（換一個收
// 事件的人）而不是錯誤 —— 雲端重連之後會這麼做。cwd 不一樣就是另一件事，回
// terminal_exists。
func (s *Service) Open(req OpenRequest, emit func(Event)) (View, error) {
	if s.opts.Disabled {
		return View{}, errf(CodeDisabled, "這台電腦的互動式終端機沒有啟用。")
	}
	if req.TerminalID == "" {
		return View{}, errf(CodeBadRequest, "沒有給 terminalId")
	}

	// 一、路徑先擋。越界要在「問使用者」之前就回，不然使用者會被問一個
	// 無論如何都不會發生的動作。
	cwd, err := s.resolveCwd(req.Cwd)
	if err != nil {
		return View{}, err
	}

	// 二、票。綁的是**原樣的 cwd**，見 approval.go 的說明。
	actionID, err := s.verify(req)
	if err != nil {
		s.audit("terminalOpen", "terminal in "+cwd, "refused", "")
		return View{}, err
	}

	s.mu.Lock()
	if existing, ok := s.terminals[req.TerminalID]; ok {
		s.mu.Unlock()
		if existing.snapshot().Cwd != cwd {
			// 同一個名字、不同的起點，是兩件事。悄悄接到舊的那一個上面，等於
			// 使用者批准了 A 資料夾、拿到的卻是一個站在 B 的 shell。
			return View{}, errf(CodeExists, "這台電腦上已經有一個叫 %s 的終端機了。", req.TerminalID)
		}
		// 重連：換一個收事件的人，並且對他重講一次 opened（他需要 pid、起始
		// 資料夾和標題才畫得出那個分頁）。留著的輸出走 terminalReplay ——
		// 重畫是呼叫端決定的事，這裡硬塞會讓已經有內容的一側看到兩份。
		view, _, err := s.Attach(req.TerminalID, emit)
		if err != nil {
			return View{}, err
		}
		existing.send(Event{
			Event: "opened", TerminalID: view.TerminalID, PID: view.PID,
			Cwd: view.Cwd, Shell: view.Shell, Title: view.Title, Cols: view.Cols, Rows: view.Rows,
		})
		return view, nil
	}
	live := 0
	for _, t := range s.terminals {
		if t.snapshot().Live {
			live++
		}
	}
	if live >= s.opts.MaxTerminals {
		s.mu.Unlock()
		return View{}, errf(CodeTooMany, "這台電腦上已經開著 %d 個終端機。", live)
	}
	// 先佔位再開，否則兩個同時進來的請求都會看到「還有空位」。
	placeholder := &session{svc: s}
	s.terminals[req.TerminalID] = placeholder
	s.mu.Unlock()

	drop := func() {
		s.mu.Lock()
		if s.terminals[req.TerminalID] == placeholder {
			delete(s.terminals, req.TerminalID)
		}
		s.mu.Unlock()
	}

	backend, err := s.resolveBackend()
	if err != nil {
		drop()
		return View{}, err
	}
	shell, err := resolveShell(envMap(s.opts.Env), s.opts.LookPath)
	if err != nil {
		drop()
		return View{}, err
	}

	cols, rows := clampSize(req.Cols, 80), clampSize(req.Rows, 24)
	handle, err := backend.Open(Spec{
		// **不帶任何旗標** —— 見套件說明。
		Argv: []string{shell},
		Cwd:  cwd,
		Env:  terminalEnv(s.opts.Env, req.Env, cwd),
		Cols: cols,
		Rows: rows,
	})
	if err != nil {
		drop()
		s.audit("terminalOpen", cwd, "error", actionID)
		return View{}, err
	}

	sess := &session{
		svc: s,
		view: View{
			TerminalID: req.TerminalID,
			Cwd:        cwd,
			Shell:      shell,
			Title:      terminalTitle(envMap(s.opts.Env), s.opts.Hostname()),
			Cols:       cols,
			Rows:       rows,
			PID:        handle.Pid(),
			Live:       true,
		},
		emit:          emit,
		handle:        handle,
		scroll:        newScrollback(s.opts.ScrollbackMaxBytes),
		stopKeepAlive: make(chan struct{}),
		pumpDone:      make(chan struct{}),
	}
	s.mu.Lock()
	s.terminals[req.TerminalID] = sess
	s.mu.Unlock()

	view := sess.snapshot()
	s.audit("terminalOpen", shell+" in "+cwd, "run", actionID)
	sess.send(Event{
		Event: "opened", TerminalID: view.TerminalID, PID: view.PID,
		Cwd: view.Cwd, Shell: view.Shell, Title: view.Title, Cols: view.Cols, Rows: view.Rows,
	})

	go sess.pump()
	go sess.keepAlive(s.opts.KeepAlive)
	go sess.reap(actionID)
	return view, nil
}

// resolveCwd 把請求裡的 cwd 變成這台電腦上一個真的、而且在授權範圍內的資料夾。
func (s *Service) resolveCwd(raw string) (string, error) {
	if raw == "" {
		if s.opts.Root == "" {
			return "", errf(CodeOutsideRoot, "這台電腦還沒有授權任何資料夾。")
		}
		return s.opts.Root, nil
	}
	if s.opts.Contain == nil {
		return "", errf(CodeOutsideRoot, "這台電腦沒有接授權檢查，所以只能從授權的資料夾開始。")
	}
	resolved, err := s.opts.Contain.Resolve(raw)
	if err != nil {
		return "", errf(CodeOutsideRoot, "%s 不在已授權的資料夾裡。", raw)
	}
	return resolved, nil
}

// Attach 換一個收事件的人，並且把留著的輸出一起交出去。
//
// 這是「重新整理之後接得回來」的那條路：新的一側先畫 replay 的內容，再接上
// 之後的事件。舊的那一個 emit 從這一刻起不會再收到東西。
func (s *Service) Attach(terminalID string, emit func(Event)) (View, []byte, error) {
	sess, err := s.get(terminalID)
	if err != nil {
		return View{}, nil, err
	}
	sess.mu.Lock()
	sess.emit = emit
	view := sess.view
	sess.mu.Unlock()
	return view, sess.scroll.bytes(), nil
}

// Input 把使用者打的位元組原樣送進去。什麼都不會被加上去 —— 連換行都不會。
func (s *Service) Input(terminalID string, data []byte) (int, error) {
	sess, err := s.getLive(terminalID)
	if err != nil {
		return 0, err
	}
	n, err := sess.handle.Write(data)
	if err != nil && err != io.EOF {
		return n, errf("write_failed", "寫不進去：%v", err)
	}
	return len(data), nil
}

// Resize 改視窗大小。**大小是夾住的，不是拒絕的**：呼叫端是一個版面，一個
// 藏起來的、正在掛載的、或是被拖到一半的面板量到的是 0 或一個小數，PTY 兩種
// 都不收 —— 拒絕會把一次普通的重繪變成一次失敗的按鍵。
func (s *Service) Resize(terminalID string, cols, rows int) (View, error) {
	sess, err := s.getLive(terminalID)
	if err != nil {
		return View{}, err
	}
	sess.mu.Lock()
	sess.view.Cols = clampSize(cols, sess.view.Cols)
	sess.view.Rows = clampSize(rows, sess.view.Rows)
	c, r := sess.view.Cols, sess.view.Rows
	view := sess.view
	sess.mu.Unlock()
	if err := sess.handle.Resize(c, r); err != nil {
		return view, errf("resize_failed", "改不了視窗大小：%v", err)
	}
	return view, nil
}

// 中斷鍵送的是**位元組**，不是訊號。
//
// 模型用的那種後端會去對前景 process group 送訊號，這樣全螢幕程式才停得掉。
// 人的終端機要的正好相反：在 vim 裡按 Ctrl-C 必須以一個位元組的身分送到 vim，
// 而不是殺掉它 —— 而那正是 line discipline 在程式把 ISIG 關掉時做的事。
// 所以三個有鍵可以按的訊號走位元組，只有沒有鍵的那兩個（SIGTERM、SIGKILL）
// 才真的去打 process group。
var controlByte = map[string]byte{
	"SIGINT":  0x03,
	"SIGQUIT": 0x1c,
	"SIGTSTP": 0x1a,
}

// Signal 送一個訊號。回傳它是以「按鍵」還是「整個 process group」送出去的。
func (s *Service) Signal(terminalID, signal string) (string, error) {
	sess, err := s.getLive(terminalID)
	if err != nil {
		return "", err
	}
	if b, ok := controlByte[signal]; ok {
		if _, err := sess.handle.Write([]byte{b}); err != nil && err != io.EOF {
			return "", errf("write_failed", "送不出去：%v", err)
		}
		return "key", nil
	}
	switch signal {
	case "SIGTERM":
		err = sess.handle.SignalGroup(SignalTerm)
	case "SIGKILL":
		err = sess.handle.SignalGroup(SignalKill)
	default:
		return "", errf(CodeBadRequest, "signal 只能是 SIGINT、SIGQUIT、SIGTSTP、SIGTERM、SIGKILL 其中一個")
	}
	if err != nil {
		return "", errf("signal_failed", "送不出訊號：%v", err)
	}
	return "group", nil
}

// Replay 是留著的全部輸出，讓一個重開的面板可以重畫，而不是對著一個其實還在
// 跑的 shell 看一個空白的方框。
func (s *Service) Replay(terminalID string) ([]byte, error) {
	sess, err := s.get(terminalID)
	if err != nil {
		return nil, err
	}
	return sess.scroll.bytes(), nil
}

// List 是現在登記在案的每一個終端機。
func (s *Service) List() []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]View, 0, len(s.terminals))
	for _, t := range s.terminals {
		if v := t.snapshot(); v.TerminalID != "" {
			out = append(out, v)
		}
	}
	return out
}

// Close 結束一個終端機。
//
// **一次關閉只產生一個結束**：紀錄在殺下去**之前**就標成「是客戶端要的」，
// 所以接著送出去的那個 exit 會帶著 ClosedByClient。
func (s *Service) Close(terminalID string) bool {
	sess, err := s.get(terminalID)
	if err != nil {
		return false
	}
	sess.mu.Lock()
	sess.closedByClient = true
	live := sess.view.Live
	sess.mu.Unlock()

	if !live {
		sess.settle(sess.snapshot().ExitCode, "")
		return true
	}
	_ = sess.handle.SignalGroup(SignalHup)
	go func() {
		time.Sleep(s.opts.DisposeGrace)
		if sess.snapshot().Live {
			_ = sess.handle.SignalGroup(SignalKill)
		}
	}()
	return true
}

// Forget 把一個終端機的紀錄和它留著的輸出丟掉。
func (s *Service) Forget(terminalID string) {
	s.mu.Lock()
	sess := s.terminals[terminalID]
	delete(s.terminals, terminalID)
	s.mu.Unlock()
	if sess != nil {
		sess.scroll.clear()
		sess.stopTicker()
	}
}

// CloseAll 關掉每一個終端機。daemon 要停、或這台機器被收回權限的時候呼叫 ——
// 一個活過 daemon 的 shell 是一個沒有人叫得動的行程。
func (s *Service) CloseAll() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.terminals))
	for id := range s.terminals {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.Close(id)
	}
	// 收尾不等寬限期：daemon 正在退出，而 SIGHUP 之後還活著的東西，
	// 留著就是留給使用者一個殺不掉的行程。
	time.Sleep(200 * time.Millisecond)
	s.mu.Lock()
	rest := make([]*session, 0, len(s.terminals))
	for _, t := range s.terminals {
		rest = append(rest, t)
	}
	s.terminals = map[string]*session{}
	s.mu.Unlock()
	for _, t := range rest {
		if t.handle != nil && t.snapshot().Live {
			_ = t.handle.SignalGroup(SignalKill)
		}
		t.stopTicker()
	}
}

func (s *Service) get(terminalID string) (*session, error) {
	s.mu.Lock()
	sess := s.terminals[terminalID]
	s.mu.Unlock()
	if sess == nil || sess.handle == nil {
		return nil, errf(CodeNoTerminal, "這台電腦上沒有叫 %s 的終端機。", terminalID)
	}
	return sess, nil
}

func (s *Service) getLive(terminalID string) (*session, error) {
	sess, err := s.get(terminalID)
	if err != nil {
		return nil, err
	}
	if !sess.snapshot().Live {
		return nil, errf(CodeExited, "終端機 %s 已經結束了。", terminalID)
	}
	return sess, nil
}

/* ------------------------------------------------------------------ *
 * 一個工作階段自己的事
 * ------------------------------------------------------------------ */

func (t *session) snapshot() View {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.view
}

func (t *session) send(e Event) {
	t.mu.Lock()
	emit := t.emit
	t.mu.Unlock()
	if emit == nil {
		return
	}
	t.emitMu.Lock()
	defer t.emitMu.Unlock()
	emit(e)
}

// pump 是唯一在讀這個終端機的 goroutine，所以輸出的順序不必另外保證。
func (t *session) pump() {
	defer close(t.pumpDone)
	buf := make([]byte, 64*1024)
	for {
		n, err := t.handle.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			t.scroll.push(chunk)
			t.send(Event{Event: "data", TerminalID: t.snapshot().TerminalID, Data: chunk})
		}
		if err != nil {
			return
		}
	}
}

// keepAlive 讓一個沒有人在打字的終端機證明自己還在。
func (t *session) keepAlive(every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopKeepAlive:
			return
		case <-ticker.C:
			if !t.snapshot().Live {
				return
			}
			t.send(Event{Event: "alive", TerminalID: t.snapshot().TerminalID})
		}
	}
}

// reap 等 shell 結束，然後**照順序**收尾：先把剩下的輸出讀完，再說結束。
func (t *session) reap(actionID string) {
	code, waitErr := t.handle.Wait()
	if waitErr != nil {
		t.svc.logf("[terminal] %s 等不到結束：%v", t.snapshot().TerminalID, waitErr)
	}
	// shell 死掉的前一刻寫的東西還在管線裡。先給泵一點時間把它讀完 ——
	// 這裡直接關掉 master 的話，那幾行就沒了。
	select {
	case <-t.pumpDone:
	case <-time.After(50 * time.Millisecond):
	}
	_ = t.handle.Close()
	// 泵結束了，才有可能不再有 data 事件排在 exit 後面。
	//
	// 但**不能無限等**：關掉 master 叫不醒讀取的平台（或一個被子孫抓著不放的
	// 描述符）會把這個 goroutine 卡死，而卡死的代價是那個終端機永遠不會回報
	// 結束 —— 面板上是一個看起來還活著、其實早就沒了的分頁。寧可讓最後一兩個
	// 位元組跟 exit 賽跑。
	select {
	case <-t.pumpDone:
	case <-time.After(2 * time.Second):
		t.svc.logf("[terminal] %s 的讀取沒有在關閉後結束", t.snapshot().TerminalID)
	}
	exit := code
	t.settle(&exit, actionID)
}

// settle 把一個終端機標成結束，並且**只說一次**。
func (t *session) settle(exitCode *int, actionID string) {
	t.mu.Lock()
	if t.settled {
		t.mu.Unlock()
		return
	}
	t.settled = true
	t.view.Live = false
	t.view.ExitCode = exitCode
	id := t.view.TerminalID
	closedByClient := t.closedByClient
	t.mu.Unlock()

	t.stopTicker()
	shown := "nil"
	if exitCode != nil {
		shown = itoa(*exitCode)
	}
	t.svc.audit("terminalOpen", "終端機 "+id+" 結束（離開碼 "+shown+"）", "run", actionID)
	t.send(Event{Event: "exit", TerminalID: id, ExitCode: exitCode, ClosedByClient: closedByClient})
}

func (t *session) stopTicker() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopKeepAlive != nil {
		select {
		case <-t.stopKeepAlive:
		default:
			close(t.stopKeepAlive)
		}
	}
}
