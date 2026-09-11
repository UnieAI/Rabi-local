package terminal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ApprovalGate 驗一張核准票。
//
// 刻意是一個**只有一個方法的窄介面**：這個套件不知道、也不該知道票是 HMAC 簽的
// 還是使用者的裝置（WebAuthn）簽的、金鑰放在哪裡、nonce 記在哪本簿子上。它只
// 負責算出「這一次要批准的到底是哪一件事」（下面的 ApprovalSubject），然後把
// 摘要交出去問。接線的人把真正的驗證器注入進來。
//
// actionID 是稽核用的：事後要看得出「這一次是誰批的」。
type ApprovalGate interface {
	VerifyApproval(tool, payloadHash, approval string) (actionID string, err error)
}

// GateFunc 讓一個函式直接當 ApprovalGate 用。
type GateFunc func(tool, payloadHash, approval string) (string, error)

// VerifyApproval 見 ApprovalGate。
func (f GateFunc) VerifyApproval(tool, payloadHash, approval string) (string, error) {
	return f(tool, payloadHash, approval)
}

// ApprovalSubjectVersion 是 subject 形狀的版本，而且它**在摘要裡面**：兩邊對
// 「一個 subject 有哪些欄位」的理解不一致時，必須大聲失敗，而不是碰巧一致。
const ApprovalSubjectVersion = 2

// ApprovalSubject 是「使用者到底批准了什麼」，序列化成一份兩邊都算得出來的位元組。
//
// # 這個函式是整個檔案的重點，而它踩過的雷寫在這裡
//
// 終端機**只在開啟的時候批一次**，之後它接受這個人打的任何東西 —— 沒有「批准
// 一次按鍵」這種事。所以卡片上誠實說得出來的只有兩件事：shell 從**哪裡**開始，
// 以及有沒有人想在裡面種環境變數。這兩件就是 subject。
//
// # cwd 綁的是雲端送下來的**原字串**，不是我們解析之後的路徑
//
// 這是最容易做錯、而且錯了會看起來像別的問題的一點。app 那一側簽票的時候手上
// 只有它送出去的那個字串；daemon 這一側如果拿 Contain.Resolve 之後的絕對路徑
// 去算摘要（symlink 被解開、結尾的斜線被清掉、相對路徑被接上 root），兩邊算的
// 就不是同一件事，而症狀是 payload_mismatch —— 一個看起來像「票壞了」其實是
// 「我們簽錯了東西」的錯誤。TS 版的 exec 與 terminalOpen 都踩過同一顆雷
// （見 canonical.mjs 的註解）。
//
// # 為什麼要自己寫 JSON
//
// 摘要要跟 runtime/packages/ava-local-protocol/src/canonical.mjs 的
// canonicalJson **一個位元組都不差**，而 Go 的 encoding/json 有兩個差異：它預設
// 會把 < > & 轉義成 \u003c 這一類（JSON.stringify 不會），而且把 0x08 / 0x0c
// 編成 \u0008 / \u000c（JSON.stringify 用 \b / \f）。所以字串轉義是照 JS 的規則
// 自己寫的；key 也照 JS 的 Object.keys().sort() —— **UTF-16 碼元順序**，不是 Go
// 的位元組順序（兩者只有在 BMP 以外的字元上會不一樣，但那一天出現的時候，
// 症狀同樣只會是一個看不懂的 payload_mismatch）。
func ApprovalSubject(cwd string, env map[string]string) []byte {
	var b strings.Builder
	b.WriteString(`{"cwd":`)
	// 空字串等同沒有給 —— canonical.mjs 的 `args.cwd ? args.cwd : null`。
	if cwd == "" {
		b.WriteString("null")
	} else {
		b.WriteString(jsonString(cwd))
	}
	b.WriteString(`,"env":{`)
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(jsonString(k))
		b.WriteString(":")
		b.WriteString(jsonString(env[k]))
	}
	b.WriteString(`},"tool":"terminalOpen","v":`)
	b.WriteString(strconv.Itoa(ApprovalSubjectVersion))
	b.WriteString("}")
	return []byte(b.String())
}

// ApprovalPayloadHash 是票綁的那個摘要：subject 的 sha256，小寫十六進位。
func ApprovalPayloadHash(cwd string, env map[string]string) string {
	sum := sha256.Sum256(ApprovalSubject(cwd, env))
	return hex.EncodeToString(sum[:])
}

// verify 在開啟終端機之前問一次「使用者批准了嗎」。
//
// **沒有注入驗證器就是一律拒絕。** 一個「沒有人檢查票」的預設值，會在接線的人
// 忘了那一行的時候，變成一台任何人都能叫它開 shell 的電腦 —— 而且從外面看
// 完全正常。
func (s *Service) verify(req OpenRequest) (string, error) {
	if s.opts.Approval == nil {
		return "", errf(CodeApprovalReq, "這台電腦上開終端機需要使用者的核准，而這個 daemon 還沒有接上核准驗證。")
	}
	if req.Approval == "" {
		return "", errf(CodeApprovalReq, "這台電腦上開終端機需要使用者的核准，而這一次沒有附上票。")
	}
	actionID, err := s.opts.Approval.VerifyApproval(
		"terminalOpen",
		ApprovalPayloadHash(req.Cwd, req.Env),
		req.Approval,
	)
	if err != nil {
		// 驗證器自己說得出代碼的話就照它的說 —— 它比這裡更知道票是怎麼壞的
		// （過期、簽章不符、被重放、這台機器只收裝置簽的票…）。
		var e *Error
		if errors.As(err, &e) {
			return "", e
		}
		return "", errf(CodeApprovalBad, "核准票被拒絕：%v", err)
	}
	return actionID, nil
}

// jsonString 照 JSON.stringify 的規則把一個字串轉義。
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// lessUTF16 照 JavaScript 排字串的方式比大小：UTF-16 碼元，不是 UTF-8 位元組。
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
