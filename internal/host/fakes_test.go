package host

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/UnieAI/Rabi-local/internal/devicekeys"
	"github.com/UnieAI/Rabi-local/internal/mcp"
	"github.com/UnieAI/Rabi-local/internal/relay"
	"github.com/UnieAI/Rabi-local/internal/runner"
	"github.com/UnieAI/Rabi-local/internal/terminal"
	"github.com/UnieAI/Rabi-local/internal/update"
)

// fakes_test.go —— 分派這一層的測試替身。
//
// **每一個都只是一個記事本**，沒有任何行為上的聰明：測試要盯的是「這個 op 有沒有
// 走到該走的地方、帶著該帶的東西」，一個會自己判斷的替身只會讓測試在替身上綠、
// 在真的東西上紅（jsdom 那一課）。

/* ── 收回報的人 ───────────────────────────────────────────────────────── */

// recorder 按**順序**記下一次 invoke 的每一則回報。順序就是這裡要測的東西之一
// （partial 必須在最終結果之前），所以它是一個 slice，不是一個 map。
type recorder struct {
	mu   sync.Mutex
	sent []relay.Result
}

func (r *recorder) emit(res relay.Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, res)
}

func (r *recorder) all() []relay.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]relay.Result{}, r.sent...)
}

// final 是最後一則，而且它必須是唯一一則非 partial。
func (r *recorder) final(t *testing.T) relay.Result {
	t.Helper()
	all := r.all()
	if len(all) == 0 {
		t.Fatal("一則回報都沒有 —— 一次 invoke 一定要有一個結果，否則雲端那端會一直等")
	}
	for i, res := range all[:len(all)-1] {
		if !res.Partial {
			t.Fatalf("第 %d 則不是 partial，卻排在最終結果前面：%+v", i, res)
		}
	}
	last := all[len(all)-1]
	if last.Partial {
		t.Fatalf("最後一則是 partial —— 那次呼叫永遠不會結束：%+v", last)
	}
	return last
}

// failure 取出一個失敗結果的代碼。
func failureCode(t *testing.T, res relay.Result) string {
	t.Helper()
	if res.OK {
		t.Fatalf("預期失敗，但拿到成功：%+v", res.Output)
	}
	f, ok := res.Output.(relay.Failure)
	if !ok {
		t.Fatalf("失敗的 output 不是 relay.Failure：%T", res.Output)
	}
	return f.Error.Code
}

func output(t *testing.T, res relay.Result) map[string]any {
	t.Helper()
	if !res.OK {
		t.Fatalf("預期成功，但拿到失敗：%+v", res.Output)
	}
	m, ok := res.Output.(map[string]any)
	if !ok {
		t.Fatalf("output 不是 map：%T", res.Output)
	}
	return m
}

/* ── 指令 ─────────────────────────────────────────────────────────────── */

// fakeCommands 假裝是 runner.Runner。onStart 讓每個測試自己決定這條指令怎麼演。
type fakeCommands struct {
	ev runner.ExecEvents

	mu         sync.Mutex
	started    []runner.ExecRequest
	cancelled  []string
	cancelAlls int

	onStart  func(f *fakeCommands, req runner.ExecRequest)
	onCancel func(f *fakeCommands, id string)
}

func (f *fakeCommands) Start(_ *runner.Scope, req runner.ExecRequest) {
	f.mu.Lock()
	f.started = append(f.started, req)
	f.mu.Unlock()
	if f.onStart != nil {
		f.onStart(f, req)
	}
}

func (f *fakeCommands) Cancel(id string) {
	f.mu.Lock()
	f.cancelled = append(f.cancelled, id)
	cb := f.onCancel
	f.mu.Unlock()
	if cb != nil {
		cb(f, id)
	}
}

func (f *fakeCommands) CancelAll() {
	f.mu.Lock()
	f.cancelAlls++
	f.mu.Unlock()
}

func (f *fakeCommands) Running() int { return 0 }

func (f *fakeCommands) lastStart(t *testing.T) runner.ExecRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.started) == 0 {
		t.Fatal("沒有任何指令被啟動")
	}
	return f.started[len(f.started)-1]
}

// exitAtOnce 是最常見的演法：指令立刻結束，沒有輸出。
func exitAtOnce(code int) func(*fakeCommands, runner.ExecRequest) {
	return func(f *fakeCommands, req runner.ExecRequest) {
		f.ev.Exit(req.ID, code, "", "")
	}
}

/* ── 終端機 ───────────────────────────────────────────────────────────── */

type fakeTerminals struct {
	available bool
	closed    int
	frames    []terminal.Frame
	// partials 是這個終端機在結束之前要講的話。
	partials []map[string]any
	result   terminal.Result
}

func (f *fakeTerminals) Dispatch(fr terminal.Frame, emit func(map[string]any)) terminal.Result {
	f.frames = append(f.frames, fr)
	for _, p := range f.partials {
		emit(p)
	}
	if f.result.Output == nil {
		return terminal.Result{OK: true, Output: map[string]any{"op": fr.Op}}
	}
	return f.result
}

func (f *fakeTerminals) Ops() []string {
	if !f.available {
		return nil
	}
	return []string{"terminalOpen", "terminalInput", "terminalResize", "terminalSignal", "terminalClose", "terminalReplay"}
}

func (f *fakeTerminals) Available() bool { return f.available }
func (f *fakeTerminals) CloseAll()       { f.closed++ }

/* ── 本機 MCP ─────────────────────────────────────────────────────────── */

type fakeMCP struct {
	available  bool
	closed     int
	listed     []string
	calls      []mcp.CallRequest
	callResult mcp.Result
}

func (f *fakeMCP) HandleList(_ context.Context, serverID string) mcp.Result {
	f.listed = append(f.listed, serverID)
	return mcp.Result{OK: true, Value: map[string]any{"servers": []any{}, "grantErrors": []any{}}}
}

func (f *fakeMCP) HandleCall(_ context.Context, req mcp.CallRequest) mcp.Result {
	f.calls = append(f.calls, req)
	if f.callResult.OK || f.callResult.Err != nil {
		return f.callResult
	}
	return mcp.Result{OK: true, Value: map[string]any{"server": req.Server, "tool": req.Tool}}
}

func (f *fakeMCP) Available() bool     { return f.available }
func (f *fakeMCP) ServerIDs() []string { return []string{"slidework"} }
func (f *fakeMCP) Close()              { f.closed++ }

/* ── 裝置金鑰 ─────────────────────────────────────────────────────────── */

type fakeDevices struct {
	devices []devicekeys.TrustedDevice
	unsafe  string
	applied []string
	applyBy []*devicekeys.Assertion
	err     error
}

func (f *fakeDevices) List() []devicekeys.TrustedDevice { return f.devices }
func (f *fakeDevices) DeviceOnly() bool                 { return len(f.devices) > 0 }
func (f *fakeDevices) DeviceOnlySince() string {
	if len(f.devices) == 0 {
		return ""
	}
	return f.devices[0].AddedAt
}
func (f *fakeDevices) Unsafe() string { return f.unsafe }

func (f *fakeDevices) Apply(enrollB64 string, by *devicekeys.Assertion) (string, string, error) {
	f.applied = append(f.applied, enrollB64)
	f.applyBy = append(f.applyBy, by)
	if f.err != nil {
		return "", "", f.err
	}
	label := "手機"
	f.devices = append(f.devices, devicekeys.TrustedDevice{
		CredentialID: "cred-abcdefghijkl", PublicKey: "pem", Label: &label, AddedAt: "2026-09-11T00:00:00.000Z",
	})
	return "add", "cred-abcdefghijkl", nil
}

/* ── 自動更新 ─────────────────────────────────────────────────────────── */

type fakeUpdater struct {
	ops []string
}

func (f *fakeUpdater) HandleOp(_ context.Context, op string, args map[string]any) (update.OpResult, bool) {
	f.ops = append(f.ops, op)
	switch op {
	case "updateCheck", "updateStatus", "updateApply":
		return update.OpResult{OK: true, Output: map[string]any{"op": op}}, true
	}
	return update.OpResult{}, false
}

/* ── 核准閘門 ─────────────────────────────────────────────────────────── */

// goodTicket 是這一組測試裡唯一有效的票。
const goodTicket = "ava1d.fake"

// acceptingGate 收 goodTicket，其餘一律拒絕。它也記下被問到的摘要 ——
// 「票綁的是不是我們正要做的那件事」靠它驗。
type acceptingGate struct {
	asked []struct{ Tool, PayloadHash, Approval string }
}

func (g *acceptingGate) VerifyApproval(tool, payloadHash, approval string) (string, error) {
	g.asked = append(g.asked, struct{ Tool, PayloadHash, Approval string }{tool, payloadHash, approval})
	if approval == goodTicket {
		return "action-1", nil
	}
	return "", &ApprovalError{Code: "approval_rejected", Message: "這張票不是這台機器的"}
}

// invoke 是一個「除了 op 與 args 之外什麼都不帶」的 invoke，給不需要票的測試用。
func invoke(op string, args map[string]any) relay.Invoke {
	raw, _ := json.Marshal(args)
	return relay.Invoke{ID: "inv-1", Op: op, Args: raw}
}
