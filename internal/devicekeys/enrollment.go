package devicekeys

import (
	"crypto/sha256"
	"time"
)

// 註冊／撤銷是整個方案的死穴。
//
// device-approval.go 的性質是「雲端偽造不出核准，因為它沒有私鑰」。那個性質
// 完全取決於這裡：如果雲端能自己把一把公鑰加進信任清單，攻擊者根本不用偽造
// 簽章 —— 註冊一把自己的，然後光明正大地簽。
//
// 所以規則只有一條，而且沒有例外：
//
//	一把新的公鑰，要嘛由一把已經信任的公鑰簽過，要嘛在那台電腦上當面確認。
//
// app 的角色只有郵差。它看得到、改不了、加不進去。
//
// 撤銷比新增更重要：手機掉了要能拔掉那一把，而**撤銷不能由雲端說了算** ——
// 否則被攻破的雲端只要把使用者所有的金鑰撤掉，就回到「只有 HMAC」的世界，
// 也就是它自己說了算。所以撤銷跟新增同一條規則，而且撤不到一把不剩。

// 註冊這條路上的每一種拒絕。
const (
	ReasonUnreadable                  Refusal = "unreadable"
	ReasonUnsupported                 Refusal = "unsupported"
	ReasonUnsigned                    Refusal = "unsigned"
	ReasonLocalConfirmNotAllowedAfter Refusal = "local_confirm_not_allowed_after_first"
	ReasonLocalConfirmAddOnly         Refusal = "local_confirm_add_only"
	ReasonSignerNotTrusted            Refusal = "signer_not_trusted"
	ReasonSelfSigned                  Refusal = "self_signed"
	ReasonWouldLeaveNone              Refusal = "would_leave_none"
	ReasonStoreUnsafe                 Refusal = "store_unsafe"
	ReasonStoreWriteFailed            Refusal = "store_write_failed"
	ReasonTooManyDevices              Refusal = "too_many_devices"
	ReasonBadPublicKey                Refusal = "bad_public_key"
)

// EnrollRequest 是一次註冊／撤銷的意圖，簽章蓋的就是它的那一串編碼。
type EnrollRequest struct {
	Op           string // "add" | "remove"
	MachineID    string
	CredentialID string
	PublicKey    string // SPKI；撤銷不需要
	Label        string
	Iat          float64
	Exp          float64
}

// EnrollmentDeps 是驗一次註冊要用到的東西。
type EnrollmentDeps struct {
	MachineID string
	// Keys 是這台機器**目前**信任的那幾把（credentialId → SPKI PEM）。
	Keys map[string]string
	// LocalConfirm 代表「使用者人就在這台電腦前面」。只有第一把用得到。
	LocalConfirm bool
	Now          time.Time
	Verifier     SignatureVerifier
}

// EnrollmentChallenge 是簽註冊請求的那個裝置要放進 WebAuthn challenge 的那串。
func EnrollmentChallenge(enrollB64 string) string {
	sum := sha256.Sum256([]byte(enrollB64))
	return b64urlEncode(sum[:])
}

// VerifyEnrollment 判斷這次註冊／撤銷算不算數。
//
// by 是**一把已經信任的**裝置簽的；nil 代表這是本機當面確認。
// 逐條對應 device-enrollment.mjs，連檢查順序都一樣。
func VerifyEnrollment(enrollB64 string, by *Assertion, deps EnrollmentDeps) (*EnrollRequest, error) {
	raw, ok := parseJSON(b64urlDecode(enrollB64))
	if !ok {
		return nil, ReasonUnreadable
	}
	if !jsStrictEqualNumber(raw, "v", 1) {
		return nil, ReasonUnsupported
	}
	if m, _ := jsString(raw, "machineId"); m != deps.MachineID {
		return nil, ReasonWrongMachine
	}
	now := nowMillis(deps.Now)
	exp, expFinite := jsNumber(raw, "exp")
	if !expFinite || now > exp {
		return nil, ReasonExpired
	}

	op, _ := jsString(raw, "op")
	credentialID, _ := jsString(raw, "credentialId")

	// ── 第一把：本機當面確認 ──────────────────────────────────────────
	//
	// 只有在**還沒有任何一把**的時候才成立。清單上已經有金鑰之後，本機確認
	// 不再是一條捷徑 —— 否則一個能在那台機器上跑程式的人就能替自己加一把，
	// 而那正是我們假設會發生的事（使用者的電腦不是可信環境，它只是**他的**）。
	if by == nil {
		if !deps.LocalConfirm {
			return nil, ReasonUnsigned
		}
		if len(deps.Keys) > 0 {
			return nil, ReasonLocalConfirmNotAllowedAfter
		}
		if op != "add" {
			return nil, ReasonLocalConfirmAddOnly
		}
		return requestFrom(raw, op, credentialID, exp), nil
	}

	// ── 其餘：要由一把已經信任的金鑰簽 ────────────────────────────────
	signerKey, trusted := deps.Keys[by.CredentialID]
	if !trusted {
		return nil, ReasonSignerNotTrusted
	}
	// **不可以自己簽自己進來。** 少了這一條，任何人送一對自產的金鑰＋自簽的
	// 請求就進得來，而那就是把整條信任鏈接到一個外人手上。
	if op == "add" && by.CredentialID == credentialID {
		return nil, ReasonSelfSigned
	}
	// 也不可以撤到零把 —— 下一次註冊就會落回「本機當面確認」那條，等於任何
	// 能在那台機器上跑程式的人都能接管。
	if op == "remove" && len(deps.Keys) <= 1 {
		return nil, ReasonWouldLeaveNone
	}

	if err := verifyWebAuthn(*by, EnrollmentChallenge(enrollB64), signerKey, deps.Verifier); err != nil {
		return nil, err
	}
	return requestFrom(raw, op, credentialID, exp), nil
}

func requestFrom(raw any, op, credentialID string, exp float64) *EnrollRequest {
	publicKey, _ := jsString(raw, "publicKey")
	label, _ := jsString(raw, "label")
	machineID, _ := jsString(raw, "machineId")
	iat, _ := jsNumber(raw, "iat")
	return &EnrollRequest{
		Op:           op,
		MachineID:    machineID,
		CredentialID: credentialID,
		PublicKey:    publicKey,
		Label:        label,
		Iat:          iat,
		Exp:          exp,
	}
}
