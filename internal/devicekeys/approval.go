package devicekeys

import (
	"bytes"
	"crypto/sha256"
	"time"
)

// ApprovalTTL 是一張裝置簽的核准最多活多久。比 HMAC 那張（兩分鐘）長一點 ——
// 生物辨識要花時間。
const ApprovalTTL = 300 * time.Second

// Refusal 是一次拒絕的理由，字串跟 TS 版**逐字相同** —— 它會原樣送回雲端，
// 而畫面、稽核列與差分測試都是靠這個字串對齊的。
type Refusal string

func (r Refusal) Error() string { return string(r) }

// 核准這條路上的每一種拒絕。順序就是檢查順序（差分測試會踩到順序）。
const (
	ReasonClaimsUnreadable     Refusal = "claims_unreadable"
	ReasonClaimsUnsupported    Refusal = "claims_unsupported"
	ReasonExpired              Refusal = "expired"
	ReasonNotYetValid          Refusal = "not_yet_valid"
	ReasonWrongMachine         Refusal = "wrong_machine"
	ReasonWrongTool            Refusal = "wrong_tool"
	ReasonPayloadMismatch      Refusal = "payload_mismatch"
	ReasonUnknownCredential    Refusal = "unknown_credential"
	ReasonClientDataUnreadable Refusal = "client_data_unreadable"
	ReasonWrongCeremony        Refusal = "wrong_ceremony"
	ReasonChallengeMismatch    Refusal = "challenge_mismatch"
	ReasonUserNotPresent       Refusal = "user_not_present"
	ReasonBadKey               Refusal = "bad_key"
	ReasonBadSignature         Refusal = "bad_signature"
	ReasonReplayed             Refusal = "replayed"
)

// Claims 是一張裝置票裡使用者的裝置真正簽下去的那幾件事。
type Claims struct {
	InvokeID    string
	MachineID   string
	Tool        string
	PayloadHash string
	// Scope 留位置給「這個動詞、N 分鐘內」那種一次簽、多次用的授權；
	// 現在一律是一次性的單一動作。
	Scope any
	Iat   float64
	Exp   float64
}

// Expect 是 daemon **正要做的那件事** —— 票必須跟它逐項對上。
type Expect struct {
	MachineID   string
	Tool        string
	PayloadHash string // 由呼叫端算（canonical.mjs 那一層，不在這個套件裡）
}

// NonceRegistry 記得「最近看過哪些核准」，用來擋重放。
//
// 跟 HMAC 票共用同一本登記簿是刻意的（兩者的 id 形狀不同，撞不到），這樣
// 「兩分鐘內看過的核准」就只有一份、也只有一個會過期的地方。
type NonceRegistry interface {
	// Seen 這個 id 之前用過了嗎。
	Seen(id string) bool
	// Remember 記下它，直到 expMillis 之後可以忘掉。
	Remember(id string, expMillis float64)
}

// ApprovalDeps 是驗一張核准要用到的東西。
type ApprovalDeps struct {
	// Keys 是 credentialId → SPKI PEM。
	//
	// **只能從這台電腦上的信任清單來（Store.Keys()）。** frame 上帶什麼公鑰都
	// 不可以放進來 —— 放得進來的話，雲端只要附上自己的公鑰就能簽任何東西，
	// 整個方案白做。
	Keys map[string]string
	// Now 是「現在」；零值代表用系統時鐘（測試就傳 time.UnixMilli(...)）。
	Now time.Time
	// Nonces 給 nil 就不擋重放（只有測試該這樣）。正式路徑一定要給 ——
	// 重放是這條路最便宜的攻擊。
	Nonces NonceRegistry
	// Verifier 不給就用 StdSignatureVerifier。
	Verifier SignatureVerifier
}

// ChallengeFor 是瀏覽器要放進 WebAuthn challenge 的那串 —— claims 的雜湊，
// 不是 claims 本身。
func ChallengeFor(claimsB64 string) string {
	sum := sha256.Sum256([]byte(claimsB64))
	return b64urlEncode(sum[:])
}

// VerifyDeviceApproval 驗一張使用者的裝置簽的核准。
//
// 逐條對應 device-approval.mjs，連檢查順序都一樣（拒絕理由會被差分測試比對）。
// 回傳的 error 一律是 Refusal。
func VerifyDeviceApproval(claimsB64 string, a Assertion, want Expect, deps ApprovalDeps) (*Claims, error) {
	raw, ok := parseJSON(b64urlDecode(claimsB64))
	if !ok {
		return nil, ReasonClaimsUnreadable
	}
	alg, _ := jsString(raw, "alg")
	if !jsStrictEqualNumber(raw, "v", 1) || alg != "webauthn" {
		return nil, ReasonClaimsUnsupported
	}

	now := nowMillis(deps.Now)
	exp, expFinite := jsNumber(raw, "exp")
	if !expFinite || now > exp {
		return nil, ReasonExpired
	}
	// 未來的票也不收 —— 時鐘歪掉或有人想把有效期往後推。
	iat, iatFinite := jsNumber(raw, "iat")
	if iatFinite && iat-60_000 > now {
		return nil, ReasonNotYetValid
	}

	if m, _ := jsString(raw, "machineId"); m != want.MachineID {
		return nil, ReasonWrongMachine
	}
	if t, _ := jsString(raw, "tool"); t != want.Tool {
		return nil, ReasonWrongTool
	}
	if p, _ := jsString(raw, "payloadHash"); p != want.PayloadHash {
		return nil, ReasonPayloadMismatch
	}

	// **這一條是整個方案的支點**：雲端沒有辦法把自己的公鑰加進這張表
	// （註冊不由它決定，見 enrollment.go）。不認得的憑證就是不認得。
	key, known := deps.Keys[a.CredentialID]
	if !known {
		return nil, ReasonUnknownCredential
	}

	if err := verifyWebAuthn(a, ChallengeFor(claimsB64), key, deps.Verifier); err != nil {
		return nil, err
	}

	invokeID, _ := jsString(raw, "invokeId")
	// 一次性：同一張票不可以用第二次。
	if deps.Nonces != nil {
		id := invokeID + ":" + a.CredentialID
		if deps.Nonces.Seen(id) {
			return nil, ReasonReplayed
		}
		deps.Nonces.Remember(id, exp)
	}

	machineID, _ := jsString(raw, "machineId")
	tool, _ := jsString(raw, "tool")
	payloadHash, _ := jsString(raw, "payloadHash")
	return &Claims{
		InvokeID:    invokeID,
		MachineID:   machineID,
		Tool:        tool,
		PayloadHash: payloadHash,
		Scope:       jsField(raw, "scope"),
		Iat:         iat,
		Exp:         exp,
	}, nil
}

// verifyWebAuthn 是核准與註冊共用的那四道：ceremony 型別、challenge 綁定、
// 使用者在場、簽章本身。
//
// 兩支檔案（device-approval.mjs / device-enrollment.mjs）在 TS 那邊是各寫一次
// 的，這裡收成一支 —— 它們逐字相同，而分成兩份的風險是只有一邊被改到。
func verifyWebAuthn(a Assertion, wantChallenge, publicKeyPEM string, verifier SignatureVerifier) error {
	clientDataRaw := b64urlDecode(a.ClientDataJSON)
	clientData, ok := parseJSON(clientDataRaw)
	if !ok {
		return ReasonClientDataUnreadable
	}
	if t, _ := jsString(clientData, "type"); t != "webauthn.get" {
		return ReasonWrongCeremony
	}
	// **challenge 綁的是這一組 claims。** 少了這一條，一張在別處取得的合法
	// assertion 可以被拿來核准任何東西。
	if c, _ := jsString(clientData, "challenge"); c != wantChallenge {
		return ReasonChallengeMismatch
	}

	authData := b64urlDecode(a.AuthenticatorData)
	// UP（使用者真的在場）那個 bit 一定要亮。沒有它，這張簽章可能來自一個
	// 沒有人碰過的驗證器 —— 那就不再是「使用者按了同意」。
	if len(authData) < 33 || authData[32]&0x01 != 0x01 {
		return ReasonUserNotPresent
	}

	if verifier == nil {
		verifier = StdSignatureVerifier{}
	}
	clientDataHash := sha256.Sum256(clientDataRaw)
	signed := bytes.Join([][]byte{authData, clientDataHash[:]}, nil)
	good, err := verifier.Verify(publicKeyPEM, signed, b64urlDecode(a.Signature))
	if err != nil {
		return ReasonBadKey
	}
	if !good {
		return ReasonBadSignature
	}
	return nil
}

// nowMillis 把一個可有可無的時間點換成 JS 那邊用的毫秒數。
func nowMillis(t time.Time) float64 {
	if t.IsZero() {
		return float64(time.Now().UnixMilli())
	}
	return float64(t.UnixMilli())
}
