package host

import (
	"errors"
	"fmt"
	"time"

	"github.com/UnieAI/Rabi-local/internal/devicekeys"
	"github.com/UnieAI/Rabi-local/internal/hmacapproval"
	"github.com/UnieAI/Rabi-local/internal/mcp"
	"github.com/UnieAI/Rabi-local/internal/terminal"
)

// approval.go —— 「使用者批准了嗎」這一道關，以及「他到底批准了什麼」怎麼算。
//
// # 這個檔案的立場：不確定就不做
//
// 每一個會改東西的 op（exec、writeFile、deleteFile、ensureDir、terminalOpen、
// mcpCall）在動手之前都要問這裡一次。**沒有注入閘門就是一律拒絕** —— 一個
// 「沒有人檢查票」的預設值，會在接線的人忘了那一行的時候，變成一台任何人都能
// 叫它跑指令的電腦，而且從外面看完全正常。
//
// 唯二不問的例外，兩個都有比票更硬的東西擋著：
//
//   - updateCheck / updateApply / updateStatus —— 閘門在**簽章**上：daemon 只裝
//     我們私鑰簽過的東西（internal/update）。這條通道能做的最壞的事，是叫一台
//     電腦去裝一個我們自己發布過的版本。
//   - deviceEnroll —— 它**自己就是簽章驗證**（VerifyEnrollment）：要嘛已信任的
//     金鑰簽過這次請求，要嘛這台機器一把都還沒有。雲端在這條路上說什麼都不算數。

// ApprovalGate 驗一張核准票。
//
// 刻意是一個**只有一個方法的窄介面**：這一層不知道、也不該知道票是 HMAC 簽的
// 還是使用者的裝置（WebAuthn）簽的、金鑰放在哪裡、nonce 記在哪本簿子上。它只
// 負責算出「這一次要批准的到底是哪一件事」（payloadHash），然後把摘要交出去問。
//
// 形狀跟 terminal.ApprovalGate 逐字相同，所以同一個實作兩邊都接得上。
//
// actionID 是稽核用的：事後要看得出「這一次是誰批的」。
type ApprovalGate interface {
	VerifyApproval(tool, payloadHash, approval string) (actionID string, err error)
}

// GateFunc 讓一個函式直接當 ApprovalGate 用（測試會用到）。
type GateFunc func(tool, payloadHash, approval string) (string, error)

// VerifyApproval 見 ApprovalGate。
func (f GateFunc) VerifyApproval(tool, payloadHash, approval string) (string, error) {
	return f(tool, payloadHash, approval)
}

// ApprovalError 是一個呼叫端不必讀句子就能分岔的拒絕。
//
// **一定帶 code** —— 雲端那端要靠它分辨「沒附票」「票被拒」「這台機器只收裝置
// 簽的票」，三者的處置完全不同（一個要請使用者按允許，一個要他改用 passkey，
// 一個是叫他去看自己的信任清單）。
type ApprovalError struct {
	Code    string
	Message string
}

func (e *ApprovalError) Error() string { return e.Message }

// codeOf 從任何一個 error 取出它的代碼；不是這裡的錯誤就回 approval_rejected。
func codeOf(err error) (string, string) {
	var e *ApprovalError
	if errors.As(err, &e) {
		return e.Code, e.Message
	}
	var t *terminal.Error
	if errors.As(err, &t) {
		return t.Code, t.Message
	}
	return "approval_rejected", fmt.Sprintf("核准票被拒絕：%v", err)
}

/* ── 真正的閘門：接到 internal/devicekeys ───────────────────────────────── */

// DeviceGate 把 devicekeys.Gate 接成 ApprovalGate。
//
// 三種結局，而且只有三種（見 devicekeys.Decision）：
//
//	Allow         —— 使用者的裝置簽過了，動作可以做。
//	DelegateHMAC  —— 這台機器還沒註冊過任何裝置，票不是裝置票 —— 交給 app 那把
//	                 共用金鑰去驗（internal/hmacapproval）。
//	其餘          —— 照 Decision 的 code 回絕。
type DeviceGate struct {
	// Gate 是 devicekeys 的那道閘。給 nil 就是這台 daemon 驗不了任何票，
	// 於是每一個會改東西的動作都會被拒絕。
	Gate *devicekeys.Gate
	// MachineID 是這台機器的身分；票上的 machineId 要跟它一致。
	MachineID string
	// HmacKey 是配對時跟 app 建立的那把共用金鑰。
	//
	// **沒有它，一台還沒註冊 passkey 的機器什麼都做不了** —— 而使用者要註冊
	// 第一把 passkey，得先有一台動得了的機器。那不是比較安全，是把人鎖在
	// 門外，而停擺正是攻擊者要的。
	//
	// 它證明的只有「這個核准經過 app 之後沒有被改」，不是「app 是誠實的」。
	// 真正的那一道在上面那個 Gate：這台機器只要註冊過任何一把金鑰，
	// DelegateHMAC 就再也不會出現。
	HmacKey []byte
	// Nonces 是防重放的登記簿，**跟裝置票共用同一本**（兩本的話同一個 nonce
	// 在兩條路上各能用一次）。
	Nonces hmacapproval.Nonces
	// Now 可注入，測試用。
	Now func() time.Time
}

// VerifyApproval 見 ApprovalGate。
func (g DeviceGate) VerifyApproval(tool, payloadHash, approval string) (string, error) {
	if g.Gate == nil {
		return "", &ApprovalError{
			Code:    "approval_required",
			Message: "這台電腦還沒接上核准機制，所以會改東西的動作一律不跑。",
		}
	}
	d := g.Gate.Require(approval, devicekeys.Expect{
		MachineID:   g.MachineID,
		Tool:        tool,
		PayloadHash: payloadHash,
	})
	switch {
	case d.Allow:
		return d.ActionID, nil
	case d.DelegateHMAC:
		// 這台機器還沒註冊任何裝置 → 用 app 那把共用金鑰驗。
		//
		// 沒有金鑰的時候**關起來**，而且說出使用者真正能做的那一件事：
		// 驗不了票還放行，等於整套核准不存在。
		if len(g.HmacKey) == 0 {
			return "", &ApprovalError{
				Code: "approval_required",
				Message: fmt.Sprintf(
					"這台電腦沒有可以驗核准票的金鑰，所以「%s」不會跑。請重新配對一次。", tool),
			}
		}
		now := time.Now
		if g.Now != nil {
			now = g.Now
		}
		c, err := hmacapproval.Verify(g.HmacKey, approval, hmacapproval.Expect{
			MachineID:   g.MachineID,
			Tool:        tool,
			PayloadHash: payloadHash,
		}, g.Nonces, now())
		if err != nil {
			// 理由要原樣傳上去：「過期」的下一步是再按一次，「摘要不對」是
			// 兩邊算錯了東西，「簽章不對」是有人動過。混成一句「票不對」的話，
			// 那三種人都會做錯事。
			return "", &ApprovalError{
				Code:    "approval_rejected",
				Message: fmt.Sprintf("核准票被拒絕：%s", err.Error()),
			}
		}
		return c.InvokeID, nil
	default:
		return "", &ApprovalError{Code: d.Code, Message: d.Message}
	}
}

/* ── 兩個接縫：terminal 與 mcp 各自要自己形狀的驗證器 ───────────────────── */

// terminalGate 把 ApprovalGate 包成 terminal 要的形狀。
//
// 轉換的重點是**錯誤代碼要活著過去**：terminal 只認得 *terminal.Error，別的
// 錯誤一律被它翻成 approval_rejected，於是「這台機器只收裝置票」會在畫面上
// 變成「你的票壞了」，而使用者會一直重按一顆解決不了問題的允許鍵。
func terminalGate(g ApprovalGate) terminal.ApprovalGate {
	if g == nil {
		return nil // terminal 自己 fail-closed（見 terminal/approval.go 的 verify）
	}
	return terminal.GateFunc(func(tool, payloadHash, approval string) (string, error) {
		id, err := g.VerifyApproval(tool, payloadHash, approval)
		if err != nil {
			code, msg := codeOf(err)
			return "", &terminal.Error{Code: code, Message: msg}
		}
		return id, nil
	})
}

// mcpApprovals 把 ApprovalGate 包成 mcp 要的形狀。
//
// subject 由 mcp 自己算（它才知道 mcpCall 的 subject 有哪些欄位），這裡只負責
// 把摘要交出去問，並且讓代碼活著回去 —— 理由同 terminalGate。
type mcpApprovals struct{ gate ApprovalGate }

// MCPApprovals 把一道閘接成 mcp.ApprovalVerifier。**gate 為 nil 就回 nil**，
// 而 mcp.Host 收到 nil 的意思正是「這台電腦驗不了票」，於是每一個會改東西的
// 呼叫都會被拒絕（mcp/host.go 的 verify）。
func MCPApprovals(g ApprovalGate) mcp.ApprovalVerifier {
	if g == nil {
		return nil
	}
	return mcpApprovals{gate: g}
}

// VerifyApproval 見 mcp.ApprovalVerifier。
func (m mcpApprovals) VerifyApproval(ticket string, subject mcp.Subject) (string, error) {
	id, err := m.gate.VerifyApproval("mcpCall", subject.PayloadHash(), ticket)
	if err != nil {
		code, msg := codeOf(err)
		return "", &mcp.Error{Code: code, Message: msg}
	}
	return id, nil
}

/* ── 「他到底批准了什麼」：subject 與它的摘要 ───────────────────────────── */

// requireApproval 在動手之前問一次。回傳的 error 為 nil 才可以做。
//
// **沒有注入閘門就是一律拒絕**，不是一律放行 —— 見檔頭。
func (h *Host) requireApproval(tool, payloadHash, approval, detail string) (string, error) {
	if h.gate == nil {
		h.audit(tool, detail, "refused", "")
		return "", &ApprovalError{
			Code:    "approval_required",
			Message: "這台電腦還沒接上核准機制，所以會改東西的動作一律不跑。",
		}
	}
	if approval == "" {
		h.audit(tool, detail, "refused", "")
		return "", &ApprovalError{
			Code:    "approval_required",
			Message: fmt.Sprintf("在這台電腦上做「%s」需要你的允許，而這一次沒有附上核准票。", tool),
		}
	}
	actionID, err := h.gate.VerifyApproval(tool, payloadHash, approval)
	if err != nil {
		h.audit(tool, detail, "refused", "")
		return "", err
	}
	return actionID, nil
}
