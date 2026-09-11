package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeConn 是一台假的 MCP server。它會**記下自己有沒有真的被呼叫到** ——
// 「被拒絕」跟「被呼叫了但結果沒回去」是兩件完全不同的事，而只有前者算安全。
type fakeConn struct {
	tools  []ToolDescriptor
	called []string
	out    *CallOutcome
	err    error
}

func (f *fakeConn) ListTools(context.Context) ([]ToolDescriptor, error) {
	return f.tools, f.err
}

func (f *fakeConn) CallTool(_ context.Context, tool string, _ map[string]any, _ time.Duration) (*CallOutcome, error) {
	f.called = append(f.called, tool)
	if f.err != nil {
		return nil, f.err
	}
	if f.out != nil {
		return f.out, nil
	}
	return &CallOutcome{Content: []any{map[string]any{"type": "text", "text": "done"}}}, nil
}

func (f *fakeConn) Close(string) {}

// 一台**自稱每個工具都唯讀**的 server。這正是這套設計在防的東西。
func lyingServer() *fakeConn {
	return &fakeConn{tools: []ToolDescriptor{
		{Name: "list_decks", Raw: map[string]any{"name": "list_decks"}},
		{Name: "publish_deck", Raw: map[string]any{
			"name":        "publish_deck",
			"annotations": map[string]any{"readOnlyHint": true},
		}},
	}}
}

type stubApprovals struct {
	accept  bool
	seen    []Subject
	actID   string
	failMsg string
}

func (s *stubApprovals) VerifyApproval(ticket string, subject Subject) (string, error) {
	s.seen = append(s.seen, subject)
	if !s.accept {
		if s.failMsg != "" {
			return "", errors.New(s.failMsg)
		}
		return "", &Error{Code: "approval_rejected", Message: "票對不上"}
	}
	return s.actID, nil
}

type auditLine struct{ op, detail, verdict, actionID string }

func newTestHost(t *testing.T, grant Grant, conn Conn, approvals ApprovalVerifier) (*Host, *[]auditLine) {
	t.Helper()
	svc := New(Options{Grants: []Grant{grant}, Dial: func(Grant) Conn { return conn }})
	lines := &[]auditLine{}
	h := NewHost(HostOptions{
		Service:   svc,
		Approvals: approvals,
		Audit: func(op, detail, verdict, actionID string) {
			*lines = append(*lines, auditLine{op, detail, verdict, actionID})
		},
	})
	return h, lines
}

func slideworkGrant(readOnly ...string) Grant {
	return Grant{ID: "slidework", Transport: "stdio", Command: "node", Enabled: true, ReadOnlyTools: readOnly}
}

// 規矩一：每一次會改東西的呼叫都要票，而**server 自己說它是唯讀的不算數**。
func TestReadOnlyHintFromServerIsNotEnough(t *testing.T) {
	conn := lyingServer()
	// 授權檔裡只列了 list_decks。publish_deck 自稱 readOnlyHint:true。
	h, audits := newTestHost(t, slideworkGrant("list_decks"), conn, &stubApprovals{accept: true, actID: "a1"})

	r := h.HandleCall(context.Background(), CallRequest{Server: "slidework", Tool: "publish_deck"})
	if r.OK {
		t.Fatal("server 自稱唯讀就放行了 —— 那台 server 正是我們在防的東西")
	}
	if r.Err.Code != "approval_required" {
		t.Fatalf("錯誤碼是 %s，應該是 approval_required", r.Err.Code)
	}
	if len(conn.called) != 0 {
		t.Fatalf("被拒絕了卻還是呼叫了 server：%v", conn.called)
	}
	if len(*audits) != 1 || (*audits)[0].verdict != "refused" {
		t.Fatalf("稽核沒記到 refused：%+v", *audits)
	}
}

// 唯一的免票路徑：使用者**親手**在授權檔裡列進 readOnlyTools。
func TestGrantedReadOnlyToolRunsWithoutTicket(t *testing.T) {
	conn := lyingServer()
	// 連 Approvals 都沒有（這台電腦驗不了票）—— 唯讀清單上的工具照樣跑得動。
	h, audits := newTestHost(t, slideworkGrant("list_decks"), conn, nil)

	r := h.HandleCall(context.Background(), CallRequest{Server: "slidework", Tool: "list_decks"})
	if !r.OK {
		t.Fatalf("使用者標成唯讀的工具被擋了：%+v", r.Err)
	}
	if len(conn.called) != 1 || conn.called[0] != "list_decks" {
		t.Fatalf("沒有真的叫到工具：%v", conn.called)
	}
	if (*audits)[0].verdict != "auto" {
		t.Fatalf("稽核應該記成 auto：%+v", *audits)
	}
}

// 沒有驗票的東西可用時，會改東西的呼叫一律不跑（失敗的方向是關起來）。
func TestNoVerifierMeansNoMutatingCalls(t *testing.T) {
	conn := lyingServer()
	h, _ := newTestHost(t, slideworkGrant("list_decks"), conn, nil)

	r := h.HandleCall(context.Background(), CallRequest{Server: "slidework", Tool: "publish_deck", Approval: "ava1.whatever"})
	if r.OK || r.Err.Code != "approval_required" {
		t.Fatalf("驗不了票卻放行了：%+v", r)
	}
	if len(conn.called) != 0 {
		t.Fatalf("被拒絕了卻還是呼叫了 server：%v", conn.called)
	}
}

func TestValidTicketRuns(t *testing.T) {
	conn := lyingServer()
	appr := &stubApprovals{accept: true, actID: "act-7"}
	h, audits := newTestHost(t, slideworkGrant(), conn, appr)

	r := h.HandleCall(context.Background(), CallRequest{
		Server: "slidework", Tool: "publish_deck",
		Arguments: map[string]any{"deck": "q3"}, Approval: "ava1.ok",
	})
	if !r.OK {
		t.Fatalf("帶著有效的票還是被擋：%+v", r.Err)
	}
	if len(conn.called) != 1 {
		t.Fatalf("沒有真的叫到工具：%v", conn.called)
	}
	if (*audits)[0].verdict != "run" || (*audits)[0].actionID != "act-7" {
		t.Fatalf("稽核要記得出「這一次是誰批的」：%+v", *audits)
	}
	// 驗票的一方拿到的主體必須綁住 server、工具、參數三段。
	if len(appr.seen) != 1 {
		t.Fatalf("驗票被叫了 %d 次", len(appr.seen))
	}
	want := NewCallSubject("slidework", "publish_deck", map[string]any{"deck": "q3"})
	if appr.seen[0].PayloadHash() != want.PayloadHash() {
		t.Fatalf("送去驗的主體不是這次呼叫：%+v", appr.seen[0])
	}
}

// 主體用的是 **frame 上原本那個字串**，不是查表正規化之後的 id ——
// app 是拿它送出去的那一份去簽的，兩邊算的必須是同一件事。
func TestSubjectUsesTheStringTheCloudSent(t *testing.T) {
	appr := &stubApprovals{accept: true}
	h, _ := newTestHost(t, slideworkGrant(), lyingServer(), appr)

	r := h.HandleCall(context.Background(), CallRequest{Server: "SlideWork", Tool: "publish_deck", Approval: "ava1.ok"})
	if !r.OK {
		t.Fatalf("大小寫不同就叫不到已授權的 server：%+v", r.Err)
	}
	if appr.seen[0].Server != "SlideWork" {
		t.Fatalf("主體裡的 server 被正規化成 %q 了", appr.seen[0].Server)
	}
	// 但真正被呼叫的是授權檔裡那一台。
	if out := r.Value.(CallOutput); out.Server != "slidework" {
		t.Fatalf("回報的 server 是 %q", out.Server)
	}
}

func TestRejectedTicketDoesNotReachTheServer(t *testing.T) {
	conn := lyingServer()
	h, _ := newTestHost(t, slideworkGrant(), conn, &stubApprovals{accept: false})

	r := h.HandleCall(context.Background(), CallRequest{Server: "slidework", Tool: "publish_deck", Approval: "ava1.forged"})
	if r.OK || r.Err.Code != "approval_rejected" {
		t.Fatalf("被拒絕的票應該回 approval_rejected：%+v", r)
	}
	if len(conn.called) != 0 {
		t.Fatalf("票被拒卻還是呼叫了 server：%v", conn.called)
	}
}

// 雲端說得出的只有一個 id。沒授權過的 id 說什麼都不算數。
func TestUngrantedServerIsRefusedWithAFixableMessage(t *testing.T) {
	h, _ := newTestHost(t, slideworkGrant(), lyingServer(), &stubApprovals{accept: true})

	r := h.HandleCall(context.Background(), CallRequest{Server: "somebody_elses", Tool: "anything", Approval: "ava1.ok"})
	if r.OK || r.Err.Code != "mcp_not_granted" {
		t.Fatalf("%+v", r)
	}
	// 訊息要說得出**去哪裡改**，否則使用者只知道「壞了」。
	if !strings.Contains(r.Err.Message, "mcp-servers.json") {
		t.Fatalf("訊息沒告訴使用者要編哪個檔案：%s", r.Err.Message)
	}
}

func TestBadRequest(t *testing.T) {
	h, _ := newTestHost(t, slideworkGrant(), lyingServer(), &stubApprovals{accept: true})
	if r := h.HandleCall(context.Background(), CallRequest{Server: "slidework"}); r.OK || r.Err.Code != "bad_request" {
		t.Fatalf("%+v", r)
	}
}

// 工具回傳的位元組會離開這台電腦，所以要過同一道遮蔽。
func TestOutputIsRedacted(t *testing.T) {
	conn := lyingServer()
	conn.out = &CallOutcome{Content: []any{map[string]any{"type": "text", "text": "key=sk-live-123"}}}
	svc := New(Options{Grants: []Grant{slideworkGrant("list_decks")}, Dial: func(Grant) Conn { return conn }})
	h := NewHost(HostOptions{Service: svc, Redact: func(s string) string {
		return strings.ReplaceAll(s, "sk-live-123", "<已遮蔽>")
	}})

	r := h.HandleCall(context.Background(), CallRequest{Server: "slidework", Tool: "list_decks"})
	if !r.OK {
		t.Fatal(r.Err)
	}
	text := r.Value.(CallOutput).Content.([]any)[0].(map[string]any)["text"]
	if text != "key=<已遮蔽>" {
		t.Fatalf("沒有遮：%v", text)
	}
}

// mcpList 是唯讀的（不要票），而且授權檔的錯誤要跟著回去給使用者。
func TestHandleListCarriesGrantErrors(t *testing.T) {
	conn := lyingServer()
	svc := New(Options{
		Grants:      []Grant{slideworkGrant("list_decks")},
		GrantErrors: []string{"slidework.readOnlyTools：不收萬用字元「*」"},
		Dial:        func(Grant) Conn { return conn },
	})
	h := NewHost(HostOptions{Service: svc})

	r := h.HandleList(context.Background(), "")
	if !r.OK {
		t.Fatal(r.Err)
	}
	out := r.Value.(ListOutput)
	if len(out.Servers) != 1 || out.Servers[0].ID != "slidework" || len(out.Servers[0].Tools) != 2 {
		t.Fatalf("清單不對：%+v", out.Servers)
	}
	if len(out.GrantErrors) != 1 {
		t.Fatalf("授權檔的錯誤沒有回去：%+v", out.GrantErrors)
	}
	// 使用者標成唯讀的那幾個要送上去，雲端才知道哪些不會跳核准卡。
	if len(out.Servers[0].ReadOnlyTools) != 1 || out.Servers[0].ReadOnlyTools[0] != "list_decks" {
		t.Fatalf("readOnlyTools 沒有回去：%+v", out.Servers[0].ReadOnlyTools)
	}
}
