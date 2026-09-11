package devicekeys

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Gate 是那道閘：一個要核准的動作送進來，它說「放行／拒絕／交給 HMAC 那條路」。
//
// # 兩種票，而且**故意**兩種都收
//
//   - 使用者的裝置簽的（WebAuthn，ava1d. 開頭）—— 私鑰在他的手機／筆電的安全
//     元件裡，從來沒有到過我們的伺服器。被攻破的 app 偽造不出來。
//   - app 用配對時那把共用金鑰簽的 HMAC 票 —— 它證明的是「這個核准經過 app
//     之後沒有被改」，**不是「app 本身是誠實的」**。
//
// 為什麼不一次砍掉 HMAC：**已經配對好的每一台機器上，裝置公鑰的數量都是零。**
// 改成只收裝置票，等於所有人的機器在更新的那一秒全部停擺，而且他們在停擺之後
// 才有機會去註冊 —— 註冊本身也走這條路。
//
// # 什麼時候變成「只收裝置簽的票」
//
// 這台機器的信任清單上**有任何一把金鑰**，HMAC 票就一律拒絕
// （device_approval_required）。開關就是清單本身，不另外存一個布林值：兩個
// 真相遲早會不一致，而不一致的那一邊會是「以為自己受保護、其實沒有」。
type Gate struct {
	store     *Store
	machineID string
	nonces    NonceRegistry
	now       func() time.Time
	verifier  SignatureVerifier
}

// GateOptions 是接一道閘要給的東西。
type GateOptions struct {
	// Store 是這台電腦的信任清單。**給 nil 就等於這個 build 不做裝置簽的
	// 核准**：每一張票都走 HMAC 那條路。
	Store *Store
	// MachineID 是這台機器的身分，票上的 machineId 要跟它一致。
	MachineID string
	// Nonces 是重放登記簿；不給就自己開一本（跟 HMAC 票共用同一本更好，
	// 見 NonceRegistry 的說明）。
	Nonces NonceRegistry
	Now    func() time.Time
	// Verifier 不給就用 StdSignatureVerifier。
	Verifier SignatureVerifier
}

// NewGate 接一道閘。
func NewGate(opts GateOptions) *Gate {
	g := &Gate{store: opts.Store, machineID: opts.MachineID, nonces: opts.Nonces, now: opts.Now, verifier: opts.Verifier}
	if g.nonces == nil {
		g.nonces = NewMemoryNonces(0)
	}
	if g.now == nil {
		g.now = time.Now
	}
	return g
}

// Decision 是那道閘的判斷。三種結局，而且**只有三種**。
type Decision struct {
	// Allow 為 true：這張裝置票驗過了，動作可以做。
	Allow bool
	// DelegateHMAC 為 true：這台機器還沒註冊過任何裝置，而票不是裝置票 ——
	// 交給呼叫端的 HMAC 驗證（這個套件刻意不碰那一段）。
	DelegateHMAC bool

	// ActionID 是票上的 invokeId（Allow 時才有），稽核列要用。
	ActionID string
	// CredentialID 是簽這張票的那把金鑰（Allow 時才有）。
	// 事後要看得出「這一次是誰批的」。
	CredentialID string

	// Code 是要回給雲端的錯誤碼（拒絕時才有）：
	// device_store_unsafe / approval_rejected / device_approval_required /
	// approval_required。
	Code string
	// Reason 是細部原因（approval_rejected 時才有），字串跟 TS 版逐字相同。
	Reason string
	// Message 是給人看的那一句。
	Message string
}

// Require 判斷 approval 這張票能不能讓 want 這件事發生。
//
// want.PayloadHash 由呼叫端算好（canonical JSON 那一層不在這個套件裡）。
func (g *Gate) Require(approval string, want Expect) Decision {
	if want.MachineID == "" {
		want.MachineID = g.machineID
	}

	// 信任清單讀不得（別的帳號寫得了、JSON 被弄壞）＝ 我們判斷不出這台機器
	// 該不該只收裝置票。這時候「退回 HMAC」看起來友善，但那正是攻擊者要的
	// 降級，所以停擺並說出原因。
	if g.store != nil {
		if unsafe := g.store.Unsafe(); unsafe != "" {
			return Decision{Code: "device_store_unsafe", Message: unsafe}
		}
	}

	if IsDeviceTicket(approval) {
		claimsB64, assertion, ok := ParseDeviceTicket(approval)
		if !ok {
			return Decision{
				Code:    "approval_rejected",
				Reason:  "malformed_device_ticket",
				Message: "approval token refused: malformed_device_ticket",
			}
		}
		var keys map[string]string
		if g.store != nil {
			// **金鑰只從這台電腦上的信任清單來。** frame 上帶什麼公鑰都讀不到
			// —— 讀得到的話，雲端只要附上自己的公鑰就能簽任何東西。
			keys = g.store.Keys()
		}
		claims, err := VerifyDeviceApproval(claimsB64, assertion, want, ApprovalDeps{
			Keys:     keys,
			Now:      g.now(),
			Nonces:   g.nonces,
			Verifier: g.verifier,
		})
		if err != nil {
			// 理由字串會原樣送回雲端，而且是差分測試比對的東西 —— 這裡不做
			// 型別斷言（一道安全閘門不應該有 panic 得了的路）。
			var reason Refusal
			if !errors.As(err, &reason) {
				reason = Refusal(err.Error())
			}
			return Decision{
				Code:    "approval_rejected",
				Reason:  string(reason),
				Message: fmt.Sprintf("device approval refused: %s", reason),
			}
		}
		return Decision{Allow: true, ActionID: claims.InvokeID, CredentialID: assertion.CredentialID}
	}

	if g.store != nil && g.store.DeviceOnly() {
		// 這台機器註冊過裝置了，所以 app 的 HMAC 票在這裡不再算數 —— 連「沒附
		// 票」都要說成這一句，否則使用者會一直重按一顆解決不了問題的允許鍵。
		return Decision{
			Code: "device_approval_required",
			Message: fmt.Sprintf(
				"%s 在這台電腦上只收你自己裝置簽的核准（已註冊 %d 把）。請在瀏覽器上用 passkey 同意這個動作。",
				want.Tool, len(g.store.List())),
		}
	}

	if approval == "" {
		return Decision{
			Code:    "approval_required",
			Message: fmt.Sprintf("%s on this machine needs the user's approval; none was attached.", want.Tool),
		}
	}

	return Decision{DelegateHMAC: true}
}

// MemoryNonces 是一本放在記憶體裡的重放登記簿。
//
// 只記到票本來就會過期為止，所以這本簿子的大小由「最近幾分鐘的核准數」決定，
// 不是由 daemon 開機多久決定。
type MemoryNonces struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]float64
	now  func() time.Time
}

// NewMemoryNonces 開一本；ttl 給 0 就用 ApprovalTTL。
func NewMemoryNonces(ttl time.Duration) *MemoryNonces {
	if ttl <= 0 {
		ttl = ApprovalTTL
	}
	return &MemoryNonces{ttl: ttl, seen: map[string]float64{}, now: time.Now}
}

// SetClock 換掉時鐘（測試用）。
func (n *MemoryNonces) SetClock(now func() time.Time) { n.now = now }

func (n *MemoryNonces) pruneLocked(at float64) {
	for id, exp := range n.seen {
		if exp < at {
			delete(n.seen, id)
		}
	}
}

// Seen 這張票之前用過了嗎。
func (n *MemoryNonces) Seen(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pruneLocked(float64(n.now().UnixMilli()))
	_, ok := n.seen[id]
	return ok
}

// Remember 記下這張票，直到它本來就會過期為止。
func (n *MemoryNonces) Remember(id string, expMillis float64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	at := float64(n.now().UnixMilli())
	n.pruneLocked(at)
	if expMillis == 0 {
		expMillis = at + float64(n.ttl.Milliseconds())
	}
	n.seen[id] = expMillis
}
