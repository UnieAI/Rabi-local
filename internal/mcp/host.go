// host.go —— 這條路上的關卡，也是 main.go 唯一要碰的東西。
//
// # 三道關，順序不能換
//
//  1. **授權**：server 必須是使用者在授權檔裡寫過的。frame 上就算帶了
//     command / cwd / env 也讀都不讀 —— 雲端只說得出一個 id。少了這一條，
//     mcpCall 就是一個繞過所有分級的 exec。
//  2. **核准**：預設每一次都要票。唯一的例外是使用者自己在授權檔裡把這個
//     工具標成唯讀（Grant.ReadOnlyTools）。
//  3. **稽核**：跑了就記，被拒也記。
//
// # 為什麼不看 annotations.readOnlyHint
//
// 那句話是**被呼叫的那個程式自己說的**，而它正是這套設計在防的對象：一個想
// 繞過核准的 server 只要把每個工具都標成唯讀就行了。所以那個欄位原樣帶回去
// 給人看（ToolDescriptor.Raw），但在這個檔案裡不存在。
package mcp

import (
	"context"
	"time"
)

// defaultCallTimeout 是 frame 沒帶期限時的上限。
const defaultCallTimeout = 120 * time.Second

// ApprovalVerifier 驗一張核准票。
//
// **這裡只定義最窄的介面**：票的格式、簽章、一次性登記都在別的套件裡，這個
// 套件不該知道那些，也不該在它們改形狀的時候跟著壞。
type ApprovalVerifier interface {
	// VerifyApproval 檢查這張票是不是使用者針對「這台 server 的這個工具、
	// 這組參數」按下的允許。
	//
	// 回傳的 actionID 會寫進稽核（事後要看得出「這一次是誰批的」）；
	// 回傳錯誤就是不准跑 —— **沒有第三種結果**。
	VerifyApproval(ticket string, subject Subject) (actionID string, err error)
}

// HostOptions 建一個 Host。
type HostOptions struct {
	// GrantsFile 授權檔路徑。空字串就用 DefaultGrantsPath()。
	//
	// 授權檔在**啟動時**讀一次，改了要重開。這是刻意的：一個每次呼叫都重讀
	// 的授權檔，等於任何能寫那個檔案的東西可以在一次對話進行到一半的時候
	// 把新的 server 塞進來，而使用者在畫面上看到的還是他當初授權的那幾台。
	GrantsFile string

	// Approvals 驗票的東西。**nil 就是「這台電腦驗不了票」**，於是每一個
	// 會改東西的呼叫都會被拒絕。失敗的方向永遠是關起來：驗不了票的時候
	// 放行，等於這整套設計不存在。
	Approvals ApprovalVerifier

	// Audit 記一筆。verdict 是 auto / run / refused / error 之一。
	Audit func(op, detail, verdict, actionID string)

	// Redact 遮蔽會離開這台電腦的字串（工具回傳的內容會經過雲端到模型供應商）。
	// 給 nil 就是不遮 —— 接不接由 main.go 決定，這個套件不自己挑一份實作。
	Redact func(string) string

	Log Logger

	// Service 注入用（測試給一個假的）。給了就不讀授權檔。
	Service *Service
}

// Host 是「本機 MCP」這條路的進入點。
type Host struct {
	svc       *Service
	approvals ApprovalVerifier
	audit     func(op, detail, verdict, actionID string)
	redact    func(string) string
	file      string
}

// NewHost 建一個 Host。**不會失敗** —— 授權檔的任何問題都變成 GrantErrors，
// 跟著每一次 mcpList 回到使用者眼前。
func NewHost(opts HostOptions) *Host {
	h := &Host{
		svc:       opts.Service,
		approvals: opts.Approvals,
		audit:     opts.Audit,
		redact:    opts.Redact,
		file:      opts.GrantsFile,
	}
	if h.file == "" {
		h.file = DefaultGrantsPath()
	}
	if h.svc == nil {
		f := LoadGrants(h.file)
		h.svc = New(Options{Grants: f.Grants, GrantErrors: f.Errors, Log: opts.Log})
	}
	return h
}

// Available 說這台機器現在叫不叫得動本機 MCP。雲端會據此決定要不要在 hello
// 裡宣傳這兩個 op —— 沒授權過任何 server 的機器就是叫不動，那是事實。
func (h *Host) Available() bool { return h.svc.Available() }

// ServerIDs 是被授權的 server id，給 hello 帶上去（畫面才講得出
// 「本機 MCP：slidework」）。
func (h *Host) ServerIDs() []string { return h.svc.ServerIDs() }

// GrantErrors 是授權檔自己的問題。
func (h *Host) GrantErrors() []string { return h.svc.GrantErrors() }

// Close 收掉所有子行程。程式結束前一定要叫。
func (h *Host) Close() { h.svc.CloseAll() }

// ListOutput 是 mcpList 的答案。
type ListOutput struct {
	Servers []ServerListing `json:"servers"`
	// GrantErrors 跟著回去，因為那是**使用者要修**的東西，而他看不到自己
	// 電腦上的 log。
	GrantErrors []string `json:"grantErrors"`
}

// HandleList 處理 mcpList：這台電腦上、使用者授權過的 server 各有什麼工具。
//
// 唯讀，所以不要票（跟列目錄同一級）。serverID 空字串就是全部。
func (h *Host) HandleList(ctx context.Context, serverID string) Result {
	if !h.svc.Available() {
		// 沒有授權任何 server 不是錯誤，是「還沒有人做過這個決定」。
		// 但要把授權檔的錯誤帶回去 —— 使用者以為自己授權了卻沒生效時，
		// 答案就在那幾行裡。
		return ok(ListOutput{Servers: []ServerListing{}, GrantErrors: h.errors()})
	}
	servers := h.svc.List(ctx, serverID)
	detail := serverID
	if detail == "" {
		detail = "*"
	}
	h.note("mcpList", detail, "auto", "")
	return ok(ListOutput{Servers: servers, GrantErrors: h.errors()})
}

// CallRequest 是 mcpCall 收到的東西。**沒有 Command / Cwd / Env** ——
// 那不是漏掉，是這個型別在說「雲端說不出要跑什麼程式」。
type CallRequest struct {
	Server    string
	Tool      string
	Arguments map[string]any
	// Approval 是使用者按下允許之後產生的票。空的就是沒票。
	Approval string
	// DeadlineMs 是雲端那一端的期限（毫秒）。0 → 用預設。
	DeadlineMs int64
}

// CallOutput 是 mcpCall 的答案，MCP tools/call 的結果原樣帶著。
type CallOutput struct {
	Server            string `json:"server"`
	Tool              string `json:"tool"`
	Content           any    `json:"content"`
	StructuredContent any    `json:"structuredContent,omitempty"`
	IsError           bool   `json:"isError"`
}

// HandleCall 處理 mcpCall：叫一次本機 MCP server 上的工具。
func (h *Host) HandleCall(ctx context.Context, req CallRequest) Result {
	if req.Server == "" || req.Tool == "" {
		return failf("bad_request", "mcpCall 要帶 server 與 tool")
	}
	detail := req.Server + "/" + req.Tool

	grant, granted := h.svc.GrantFor(req.Server)
	if !granted {
		h.note("mcpCall", detail, "refused", "")
		return failf("mcp_not_granted",
			"這台電腦上沒有授權過名叫「%s」的 MCP server。要授權請編輯 %s。", req.Server, h.file)
	}

	args := req.Arguments
	if args == nil {
		args = map[string]any{}
	}

	// **唯一的免票路徑**：使用者親手把這個工具列進 readOnlyTools。
	// 注意這裡看的是 grant，不是 server 回報的 annotations —— 見檔頭。
	actionID := ""
	if !grant.IsReadOnlyTool(req.Tool) {
		// subject 用 **frame 上原本那個字串**（req.Server），不是 grant.ID：
		// app 是拿它送出去的那一份去簽的，這邊先正規化再算的話，兩邊算的就
		// 不是同一件事，症狀是一個看起來像「票壞了」的 payload_mismatch。
		subject := NewCallSubject(req.Server, req.Tool, args)
		id, err := h.verify(req.Approval, subject)
		if err != nil {
			h.note("mcpCall", detail, "refused", "")
			return fail(err)
		}
		actionID = id
	}

	verdict := "auto"
	if actionID != "" {
		verdict = "run"
	}
	h.note("mcpCall", detail, verdict, actionID)

	// **比雲端的期限早一點放棄。** 兩邊同時到期的話先講話的是雲端，而它只
	// 說得出「那台機器沒回應」—— 使用者看到的是「我的電腦壞了」。早兩秒放棄，
	// 錯誤就會是這邊給的那一句「你那台 server 沒回話」。
	timeout := defaultCallTimeout
	if req.DeadlineMs > 0 {
		timeout = time.Duration(req.DeadlineMs) * time.Millisecond
	}
	timeout -= 2 * time.Second
	if timeout < time.Second {
		timeout = time.Second
	}

	out, err := h.svc.Call(ctx, grant.ID, req.Tool, args, timeout)
	if err != nil {
		h.note("mcpCall", detail, "error", actionID)
		if e, isOurs := err.(*Error); isOurs {
			return fail(e)
		}
		return failf("mcp_failed", "%v", err)
	}

	return ok(CallOutput{
		Server: grant.ID,
		Tool:   req.Tool,
		// 工具回傳的東西跟 stdout、檔案內容一樣，是**要離開這台電腦**的位元組。
		// 所以走同一道遮蔽 —— 一台接檔案系統的本機 MCP server 讀到 .env 是
		// 完全正常的一天。
		Content:           h.scrub(out.Content),
		StructuredContent: h.scrub(out.StructuredContent),
		IsError:           out.IsError,
	})
}

// verify 是「要不要票」判斷之後的那一步。回 nil 才算放行。
func (h *Host) verify(ticket string, subject Subject) (string, *Error) {
	if h.approvals == nil {
		// 驗不了票的時候放行，等於這整套設計不存在。
		return "", errf("approval_required",
			"這台電腦還沒接上核准機制，所以會改東西的 MCP 呼叫一律不跑。")
	}
	if ticket == "" {
		return "", errf("approval_required",
			"在這台電腦上跑「%s」需要你的允許，而這次沒有附上核准。", subject.Tool)
	}
	id, err := h.approvals.VerifyApproval(ticket, subject)
	if err != nil {
		if e, isOurs := err.(*Error); isOurs {
			return "", e
		}
		return "", errf("approval_rejected", "核准票被拒絕：%v", err)
	}
	return id, nil
}

func (h *Host) errors() []string {
	if e := h.svc.GrantErrors(); e != nil {
		return e
	}
	return []string{}
}

func (h *Host) note(op, detail, verdict, actionID string) {
	if h.audit != nil {
		h.audit(op, detail, verdict, actionID)
	}
}

// scrub 把遮蔽套到工具回傳的每一個字串上。結構原封不動 —— 雲端那端要靠
// content 的形狀去顯示（文字、圖片、資源），改了形狀就顯示不出來。
func (h *Host) scrub(v any) any {
	if h.redact == nil || v == nil {
		return v
	}
	switch t := v.(type) {
	case string:
		return h.redact(t)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = h.scrub(x)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = h.scrub(x)
		}
		return out
	default:
		return v
	}
}
