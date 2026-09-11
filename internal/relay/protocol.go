package relay

import "encoding/json"

// 這個檔案是**線路的形狀**，而線路的定義在
// `runtime/packages/ava-local-protocol/src/protocol.mjs`。兩邊不一致的症狀
// 不是編譯錯誤，是「連上了，但什麼都不會發生」。
//
// ## 為什麼舊的那一組欄位整批換掉
//
// 這個客戶端原本說的是 eve 分支的 `/v1/desktop/relay/*`：下行 `{t:"exec"}`、
// 上行批次送 `{t,id,data}`。**ava 分支刻意不提供那組路由**，理由寫在
// `runtime/apps/sandbox-runtime/src/shared/auth.mjs`：
//
//   它的信任單位是**使用者**不是機器 —— 呼叫端證明「我是使用者 X」，然後在
//   query parameter 裡愛寫哪個 machineId 就寫哪個。Rabi Local 改成每一台機器
//   自己一張 bearer device token，app 在代理之前就把它解析成唯一一列
//   user_machines，所以 machineId 從來不是呼叫端說了算的東西。
//
// 所以這不是「協定比較舊」，是對著一個因為安全理由被否決的設計寫的。

// Invoke 是雲端送下來要這台電腦做的一件事。
//
//	invoke { id, op, args, approval?, deadlineMs? }
//
// `Args` 保持成原始 JSON：每個 op 的參數形狀不同（exec 的 command/cwd、
// mcpCall 的 server/tool/arguments、terminalOpen 的 cwd/env…），在這一層解成
// 一個大聯集結構，只會讓每加一個 op 就要改線路層。交給處理端各自解。
type Invoke struct {
	ID string `json:"id"`
	Op string `json:"op"`
	// 原封不動的那一份。**核准票綁的是這些位元組的摘要**，在這裡重新序列化
	// 一次就可能改變 key 的順序或跳脫，而那等於 payload_mismatch。
	Args json.RawMessage `json:"args"`
	// 使用者的核准票。`ava1d.` 開頭是他的裝置簽的，其餘是 app 的 HMAC 票。
	Approval   string `json:"approval"`
	DeadlineMs int64  `json:"deadlineMs"`
}

// Down 是 SSE 上送下來的任何一則。
//
// `type` 不是 `t` —— 伺服器送的是 `{ type: "invoke", … }`
// （sandbox-runtime 的 relay/registry.mjs）。這一個字母的差別會讓整個客戶端
// 安靜地什麼都收不到：JSON 解得開、欄位是空的、switch 沒有一條命中。
type Down struct {
	Type       string          `json:"type"`
	ID         string          `json:"id"`
	Op         string          `json:"op"`
	Args       json.RawMessage `json:"args"`
	Approval   string          `json:"approval"`
	DeadlineMs int64           `json:"deadlineMs"`
	// revoke 帶的理由，給使用者看。
	Reason string `json:"reason"`
}

// AsInvoke 把一則 down 轉成 Invoke；不是 invoke 就回 false。
func (d Down) AsInvoke() (Invoke, bool) {
	if d.Type != "invoke" || d.ID == "" || d.Op == "" {
		return Invoke{}, false
	}
	args := d.Args
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	return Invoke{ID: d.ID, Op: d.Op, Args: args, Approval: d.Approval, DeadlineMs: d.DeadlineMs}, true
}

// Result 是一次 invoke 的回報：`POST /api/machines/relay/result`。
//
//	{ id, ok, output, partial? }
//
// ## partial 與最終結果**必須照順序送**
//
// 這條路踩過一次（2026-09-06，TS 版）：輸出與結束是兩個獨立的 HTTP 請求，
// 誰先到沒有人管。指令越快，結束越容易超車 —— 而 relay 在最終結果落地的
// 當下就把待辦刪掉，於是被超車的輸出撞上「找不到這個 id」被靜靜丟掉。
// 實測五個 echo 連著跑，兩個的 stdout 整段不見而 exit 仍然是 0，模型於是
// 對著一個不存在的世界推理。
//
// 所以上行是**一條佇列、一次一個 POST**，不是併發 fire-and-forget。
type Result struct {
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Output  any    `json:"output"`
	Partial bool   `json:"partial,omitempty"`
}

// Failure 是 `output` 在失敗時的形狀，對應伺服器的 relayError()。
type Failure struct {
	Error FailureBody `json:"error"`
}

type FailureBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Fail 組一個失敗的結果。**錯誤碼要是機器分得出來的那一組**（workspace_escape、
// approval_required…）—— 使用者看得懂的那句話在 message 裡，而模型的下一步
// 取決於碼，不是取決於句子。
func Fail(id, code, message string) Result {
	return Result{ID: id, OK: false, Output: Failure{Error: FailureBody{Code: code, Message: message}}}
}

// OK 組一個成功的結果。
func Done(id string, value any) Result {
	return Result{ID: id, OK: true, Output: value}
}
