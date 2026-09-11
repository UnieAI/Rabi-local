// Package hmacapproval 驗 app 用配對時那把共用金鑰簽的核准票。
//
// 移植自 runtime/packages/ava-local-protocol/src/approval.mjs。
//
// ## 它證明的是什麼、不證明什麼
//
// 這張票證明「這個核准**經過 app 之後沒有被改**」。它**不**證明「app 本身是
// 誠實的」—— 金鑰是 app 跟這台機器共用的，所以能在 app 行程裡執行程式碼的人
// 簽得出任何一張票，使用者不必按任何東西（ADR-0005 自己寫著這個限制）。
//
// 真正的那一道是使用者的裝置簽的（internal/devicekeys）。
//
// ## 那為什麼還要收 HMAC 票
//
// **已經配對好的每一台機器上，裝置公鑰的數量都是零。** 改成只收裝置票，等於
// 所有人的機器在更新的那一秒全部停擺 —— 而他們要註冊第一把 passkey，得先有
// 一台還動得了的機器。
//
// 這個套件一度沒被移植，於是 Go 版對一台還沒註冊 passkey 的機器**什麼都不讓
// 做**。那不是「比較安全」，那是把使用者鎖在門外，而且比 TS 版更嚴的那一步
// 沒有讓任何人更安全 —— 攻擊者要的正是這種停擺。
//
// 開關仍然在信任清單：這台機器只要註冊過任何一把金鑰，HMAC 票就一律拒絕
// （判斷在 devicekeys.Gate，不在這裡）。
package hmacapproval

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// Claims 是票裡宣告的東西。
type Claims struct {
	V           int    `json:"v"`
	Alg         string `json:"alg"`
	InvokeID    string `json:"invokeId"`
	MachineID   string `json:"machineId"`
	UserID      string `json:"userId"`
	SessionID   string `json:"sessionId"`
	Tool        string `json:"tool"`
	PayloadHash string `json:"payloadHash"`
	Iat         int64  `json:"iat"`
	Exp         int64  `json:"exp"`
	Nonce       string `json:"nonce"`
}

// Expect 是驗票的人手上那份事實。
//
// `InvokeID` 刻意可以留空：app 在 sandbox-runtime 指派 relay 的 invoke id
// **之前**就把票簽好了，所以 daemon 綁的是「機器 ＋ 工具 ＋ 參數摘要 ＋ nonce」，
// 只有在呼叫端手上真的有一個可以比的 id 時才比它。
type Expect struct {
	MachineID   string
	Tool        string
	PayloadHash string
	InvokeID    string // 空 = 不比
}

// Nonces 是用過的 nonce 登記簿，防重放。**跟裝置票共用同一本** —— 兩本的話，
// 同一個 nonce 在兩條路上各能用一次。
type Nonces interface {
	Has(nonce string, now int64) bool
	Add(nonce string, exp int64, now int64)
}

// Refusal 是拒絕的理由。字串跟 TS 版逐字相同：模型與稽核都照著它分辨下一步。
type Refusal string

const (
	Malformed       Refusal = "malformed"
	BadSignature    Refusal = "bad_signature"
	Expired         Refusal = "expired"
	MachineMismatch Refusal = "machine_mismatch"
	ToolMismatch    Refusal = "tool_mismatch"
	InvokeMismatch  Refusal = "invoke_mismatch"
	PayloadMismatch Refusal = "payload_mismatch"
	Replayed        Refusal = "replayed"
)

func (r Refusal) Error() string { return string(r) }

// Verify 驗一張 HMAC 票。`key` 是配對時建立的那把，每台機器一把。
func Verify(key []byte, token string, want Expect, nonces Nonces, now time.Time) (*Claims, error) {
	claimsB64, sigB64, ok := strings.Cut(token, ".")
	if !ok || claimsB64 == "" || sigB64 == "" {
		return nil, Malformed
	}
	raw, err := b64urlDecode(claimsB64)
	if err != nil {
		return nil, Malformed
	}
	var c Claims
	if json.Unmarshal(raw, &c) != nil {
		return nil, Malformed
	}
	sig, err := b64urlDecode(sigB64)
	if err != nil {
		return nil, Malformed
	}

	// **簽章先驗。** 先比內容再比簽章的話，一個攻擊者可以用錯誤訊息當神諭，
	// 一格一格問出他該偽造什麼。
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(claimsB64))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, BadSignature
	}

	ms := now.UnixMilli()
	if c.Exp == 0 || ms > c.Exp {
		return nil, Expired
	}
	if c.MachineID != want.MachineID {
		return nil, MachineMismatch
	}
	if c.Tool != want.Tool {
		return nil, ToolMismatch
	}
	if want.InvokeID != "" && c.InvokeID != want.InvokeID {
		return nil, InvokeMismatch
	}
	if want.PayloadHash == "" || c.PayloadHash != want.PayloadHash {
		return nil, PayloadMismatch
	}
	if nonces != nil {
		if nonces.Has(c.Nonce, ms) {
			return nil, Replayed
		}
		nonces.Add(c.Nonce, c.Exp, ms)
	}
	return &c, nil
}

// b64urlDecode 照 Node 的寬鬆規則：不要求 padding。
//
// Go 的 RawURLEncoding 比 Node 嚴格，同一張票會在兩邊得到不同的拒絕理由 ——
// 而「格式壞了」跟「簽章不對」對查問題的人是完全不同的兩條線索。
func b64urlDecode(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
