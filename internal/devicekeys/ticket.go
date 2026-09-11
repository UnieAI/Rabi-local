package devicekeys

import "strings"

// TicketPrefix 是裝置簽的票的前綴。
//
// 為什麼不開一個新的 frame 欄位：一張核准從 app 走到 daemon 要經過三層，而
// 中間那兩層對 approval 這個欄位做的事只有一件 —— 原樣往下傳。它們讀不懂票，
// 也因此改不了票，那正是我們要的性質。開新欄位的話兩層都要跟著改，而且從此
// 有兩條路要維護。
//
// 認得出來而且不會認錯：HMAC 票是 base64url(JSON).base64url(sig)，JSON 一定以
// `{"v":1` 開頭，所以 base64url 一定以 `ey` 開頭 —— `ava1d.` 不可能跟它撞。
// 版本號寫在前綴裡是為了以後換簽章格式時，舊 daemon 看到的是「我不認得這種
// 票」而不是「這張票壞了」。
const TicketPrefix = "ava1d."

// Assertion 是一次 WebAuthn 簽章，四個欄位都是 base64url 字串。
type Assertion struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

// IsDeviceTicket 這張票是不是裝置簽的（而不是 app 的 HMAC 票）。
func IsDeviceTicket(token string) bool { return strings.HasPrefix(token, TicketPrefix) }

// ParseDeviceTicket 拆開一張裝置票：`ava1d.<claims>.<assertion>`。
//
// **壞掉一律回 ok=false，不 panic** —— 這條路上的輸入全部來自網路，而一個沒有
// 接住的例外會變成「那台機器沒回應」，那句話跟真正的原因（票的格式不對）差
// 很遠。
func ParseDeviceTicket(token string) (claimsB64 string, a Assertion, ok bool) {
	if !IsDeviceTicket(token) {
		return "", Assertion{}, false
	}
	rest := token[len(TicketPrefix):]
	dot := strings.Index(rest, ".")
	if dot <= 0 || dot == len(rest)-1 {
		return "", Assertion{}, false
	}
	body, parsed := parseJSON(b64urlDecode(rest[dot+1:]))
	if !parsed {
		return "", Assertion{}, false
	}
	// 陣列與非物件都不算（JS 那邊是 typeof/Array.isArray 兩道）；欄位必須是
	// **非空字串**，四個少一個就不是一張票。
	if _, isObj := body.(map[string]any); !isObj {
		return "", Assertion{}, false
	}
	fields := [4]*string{&a.CredentialID, &a.AuthenticatorData, &a.ClientDataJSON, &a.Signature}
	for i, name := range [4]string{"credentialId", "authenticatorData", "clientDataJSON", "signature"} {
		s, isStr := jsString(body, name)
		if !isStr || s == "" {
			return "", Assertion{}, false
		}
		*fields[i] = s
	}
	return rest[:dot], a, true
}

// AssertionFrom 把 frame 上那個形狀不明的 `by` 正規化成一次簽章。
//
// 對應 TS 的 asAssertion＋deviceEnroll 那兩段：**不是物件（或是陣列）就是
// nil，也就是「本機當面確認」**；是物件就一定走簽章那條路，缺的欄位變成空
// 字串，驗章自然過不了。少了這一步，一個亂寫的 by 會掉進本機確認那一條 ——
// 那是一條把註冊送給任何人的捷徑。
func AssertionFrom(v any) *Assertion {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return nil
	}
	return &Assertion{
		CredentialID:      jsToString(m["credentialId"]),
		AuthenticatorData: jsToString(m["authenticatorData"]),
		ClientDataJSON:    jsToString(m["clientDataJSON"]),
		Signature:         jsToString(m["signature"]),
	}
}
