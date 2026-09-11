// client.go —— 在**本機**跟一台 MCP server 講話（stdio + JSON-RPC 2.0）。
//
// 線上就是一行一則 JSON，走子行程的 stdin/stdout。握手是
// initialize → notifications/initialized，之後 tools/list 與 tools/call。
//
// # 三個坑，先寫起來
//
//   - **stdout 只能有 JSON。** 很多 server 會把 log 印在 stdout 上，一行壞掉
//     不能讓整條連線死掉 —— 解不開的行丟掉並記一筆，不是讓呼叫失敗。
//     （server 的 log 該走 stderr，但那是它的事，不是我們的。）
//   - **一定要有逾時。** 一台 MCP server 可以就這樣不回答；這裡沒有計時器的
//     話，雲端那一次呼叫會一路卡到 relay 的上限，使用者看到的是「agent 沒反應」
//     而不是「你那台 server 沒回話」。
//   - **行程要收得掉。** 使用者按停止、或這台閒置太久，子行程必須跟著走，
//     否則他的電腦上留著一排沒有人碰得到的程式。
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// protocolVersion 是我們認得哪一版 MCP。server 會回它自己的，我們照收。
const protocolVersion = "2025-06-18"

const (
	defaultRequestTimeout = 60 * time.Second
	// idleShutdown：閒置多久就把子行程收掉。使用者的電腦不是伺服器，
	// 不該為了我們養一排常駐程式。
	idleShutdown = 10 * time.Minute
)

// ToolDescriptor 是 server 回報的一個工具。**原樣**留著（Raw）是因為雲端要
// 顯示 description 與 inputSchema，而我們不該替 server 決定哪些欄位重要。
//
// 特別注意 Raw 裡可能有 annotations.readOnlyHint —— 那是 server 自己說的，
// 帶回去給人看可以，**但它永遠不決定要不要票**（見 host.go）。
type ToolDescriptor struct {
	Name string
	Raw  map[string]any
}

// MarshalJSON 讓這個工具原樣回到雲端。
func (t ToolDescriptor) MarshalJSON() ([]byte, error) {
	if t.Raw == nil {
		return json.Marshal(map[string]any{"name": t.Name})
	}
	return json.Marshal(t.Raw)
}

// UnmarshalJSON 收下 server 給的整個物件，順手把 name 拆出來。
func (t *ToolDescriptor) UnmarshalJSON(b []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	t.Raw = raw
	t.Name, _ = raw["name"].(string)
	return nil
}

// CallOutcome 是 tools/call 的結果，原樣轉回雲端。
type CallOutcome struct {
	Content           any  `json:"content"`
	StructuredContent any  `json:"structuredContent,omitempty"`
	IsError           bool `json:"isError"`
}

// Conn 是「一台 server 的連線」這件事的最小介面。Service 只認這個，所以測試
// 可以塞一台假的 server 進去，不必真的起一個行程。
type Conn interface {
	ListTools(ctx context.Context) ([]ToolDescriptor, error)
	CallTool(ctx context.Context, tool string, args map[string]any, timeout time.Duration) (*CallOutcome, error)
	Close(why string)
}

type pending struct {
	result json.RawMessage
	err    error
}

// stdioConn 是一台 server 的實際連線：懶啟動、用完留著、閒置就收。
type stdioConn struct {
	grant   Grant
	log     Logger
	timeout time.Duration

	// startMu 讓「起一台 server」一次只有一個人在做。兩個同時進來的呼叫
	// 各 spawn 一份的話，使用者的電腦上會多出一個沒有人收得掉的行程。
	startMu sync.Mutex

	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	nextID  int64
	waiting map[int64]chan pending
	dead    bool
	idle    *time.Timer
}

func newStdioConn(g Grant, log Logger, timeout time.Duration) *stdioConn {
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	return &stdioConn{grant: g, log: log, timeout: timeout, dead: true, waiting: map[int64]chan pending{}}
}

func (c *stdioConn) alive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.dead && c.stdin != nil
}

// ensure 起 server 並握手。起不來時**不留下半個狀態** —— 下一次呼叫會重試，
// 不然使用者把 server 修好了還要重開這個程式才會再試一次。
func (c *stdioConn) ensure(ctx context.Context) error {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	if c.alive() {
		return nil
	}
	if err := c.spawn(); err != nil {
		return err
	}
	if _, err := c.request(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "copilot-desktop", "version": "0.1.0"},
	}, c.timeout); err != nil {
		c.Close("握手失敗")
		return err
	}
	c.notify("notifications/initialized", map[string]any{})
	return nil
}

func (c *stdioConn) spawn() error {
	// **不經過 shell。** 授權檔裡的 command 與 args 原樣交給作業系統，否則
	// 一個含空白或分號的參數就變成第二條指令。
	cmd := exec.Command(c.grant.Command, c.grant.Args...)
	cmd.Dir = c.grant.Cwd
	cmd.Env = ChildEnv(os.Environ(), c.grant.Env)
	// server 的 stderr 是它自己的 log。**不往雲端送**（那是它的內部細節，
	// 而且常常帶著路徑與環境資訊），只在本機留一行。
	cmd.Stderr = logWriter{log: c.log, id: c.grant.ID}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return errf("mcp_spawn_failed", "%s：接不上輸入 —— %v", c.grant.ID, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return errf("mcp_spawn_failed", "%s：接不上輸出 —— %v", c.grant.ID, err)
	}
	if err := cmd.Start(); err != nil {
		// 這是最常見的一種失敗（打錯路徑、那個程式沒裝），所以訊息裡一定要
		// 有 server 的 id 和真正的系統錯誤 —— 使用者要靠這一句去改授權檔。
		return errf("mcp_spawn_failed", "%s：起不來 —— %v", c.grant.ID, err)
	}

	c.mu.Lock()
	c.cmd = cmd
	c.stdin = stdin
	c.dead = false
	c.nextID = 1
	c.waiting = map[int64]chan pending{}
	c.mu.Unlock()

	go c.readLoop(stdout, cmd)
	c.touch()
	return nil
}

func (c *stdioConn) readLoop(stdout io.ReadCloser, cmd *exec.Cmd) {
	r := bufio.NewReader(stdout)
	for {
		line, err := r.ReadString('\n')
		if s := strings.TrimSpace(line); s != "" {
			c.onLine(s)
		}
		if err != nil {
			break
		}
	}
	// 讀到底了才 Wait —— 反過來的話會在 server 還在講話的時候關掉管線。
	werr := cmd.Wait()
	c.failAll(errf("mcp_server_exited", "%s：行程結束了（%s）", c.grant.ID, waitReason(werr)))
}

func waitReason(err error) string {
	if err == nil {
		return "正常結束"
	}
	return err.Error()
}

func (c *stdioConn) onLine(line string) {
	var msg struct {
		ID     *int64          `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		// server 把 log 印在 stdout 上是常見的壞習慣。丟掉那一行，不要讓它
		// 把整條連線帶走。
		c.log.printf("[mcp:%s] stdout 上有非 JSON 的一行，已忽略", c.grant.ID)
		return
	}
	if msg.ID == nil {
		return // server 主動送的通知，這一版不處理
	}
	c.mu.Lock()
	ch, has := c.waiting[*msg.ID]
	delete(c.waiting, *msg.ID)
	c.mu.Unlock()
	if !has {
		return
	}
	if msg.Error != nil {
		ch <- pending{err: errf("mcp_error", "%s：%s", c.grant.ID, msg.Error.Message)}
		return
	}
	ch <- pending{result: msg.Result}
}

func (c *stdioConn) failAll(e *Error) {
	c.mu.Lock()
	c.dead = true
	c.stdin = nil
	waiting := c.waiting
	c.waiting = map[int64]chan pending{}
	c.mu.Unlock()
	for _, ch := range waiting {
		ch <- pending{err: e}
	}
}

func (c *stdioConn) notify(method string, params any) {
	c.mu.Lock()
	stdin := c.stdin
	c.mu.Unlock()
	if stdin == nil {
		return
	}
	line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	if err != nil {
		return
	}
	_, _ = stdin.Write(append(line, '\n'))
}

func (c *stdioConn) request(ctx context.Context, method string, params any, timeout time.Duration) (json.RawMessage, error) {
	if timeout <= 0 {
		timeout = c.timeout
	}
	c.mu.Lock()
	if c.dead || c.stdin == nil {
		c.mu.Unlock()
		return nil, errf("mcp_not_running", "%s：連線不在了", c.grant.ID)
	}
	id := c.nextID
	c.nextID++
	ch := make(chan pending, 1)
	c.waiting[id] = ch
	stdin := c.stdin
	c.mu.Unlock()

	line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		c.forget(id)
		return nil, errf("mcp_bad_request", "%s：%s 的參數編不成 JSON —— %v", c.grant.ID, method, err)
	}
	if _, err := stdin.Write(append(line, '\n')); err != nil {
		c.forget(id)
		return nil, errf("mcp_not_running", "%s：寫不進去 —— %v", c.grant.ID, err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case p := <-ch:
		return p.result, p.err
	case <-timer.C:
		c.forget(id)
		return nil, errf("mcp_timeout", "%s：%s 超過 %s 沒有回應", c.grant.ID, method, timeout)
	case <-ctx.Done():
		c.forget(id)
		return nil, errf("mcp_cancelled", "%s：%s 被取消了", c.grant.ID, method)
	}
}

func (c *stdioConn) forget(id int64) {
	c.mu.Lock()
	delete(c.waiting, id)
	c.mu.Unlock()
}

// touch 重設閒置計時器。每一次成功的往返都叫一次。
func (c *stdioConn) touch() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idle != nil {
		c.idle.Stop()
	}
	c.idle = time.AfterFunc(idleShutdown, func() { c.Close("閒置太久") })
}

func (c *stdioConn) ListTools(ctx context.Context) ([]ToolDescriptor, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, err
	}
	c.touch()
	raw, err := c.request(ctx, "tools/list", map[string]any{}, c.timeout)
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []ToolDescriptor `json:"tools"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, errf("mcp_bad_response", "%s：tools/list 的回覆看不懂 —— %v", c.grant.ID, err)
		}
	}
	return out.Tools, nil
}

func (c *stdioConn) CallTool(ctx context.Context, tool string, args map[string]any, timeout time.Duration) (*CallOutcome, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, err
	}
	c.touch()
	if args == nil {
		args = map[string]any{}
	}
	raw, err := c.request(ctx, "tools/call", map[string]any{"name": tool, "arguments": args}, timeout)
	if err != nil {
		return nil, err
	}
	out := &CallOutcome{Content: []any{}}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, errf("mcp_bad_response", "%s：tools/call 的回覆看不懂 —— %v", c.grant.ID, err)
		}
	}
	if out.Content == nil {
		out.Content = []any{}
	}
	return out, nil
}

// Close 收掉這台 server。先關 stdin（守規矩的 server 會自己走），寬限之後
// 再真的殺 —— 不殺的話「使用者按了停止」會變成「那個程式還在跑」。
func (c *stdioConn) Close(why string) {
	c.mu.Lock()
	if c.idle != nil {
		c.idle.Stop()
		c.idle = nil
	}
	cmd := c.cmd
	stdin := c.stdin
	c.cmd = nil
	c.mu.Unlock()

	if stdin != nil {
		_ = stdin.Close()
	}
	if cmd != nil && cmd.Process != nil {
		proc := cmd.Process
		time.AfterFunc(500*time.Millisecond, func() { _ = proc.Kill() })
	}
	c.failAll(errf("mcp_closed", "%s：連線已關閉（%s）", c.grant.ID, why))
}

// logWriter 把 server 的 stderr 變成本機的一行 log，並且**截短** ——
// 一台會刷屏的 server 不該把使用者的磁碟寫滿。
type logWriter struct {
	log Logger
	id  string
}

func (w logWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if line != "" {
		if len(line) > 500 {
			line = line[:500]
		}
		w.log.printf("[mcp:%s] %s", w.id, line)
	}
	return len(p), nil
}
