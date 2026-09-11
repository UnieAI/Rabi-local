package host

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/UnieAI/Rabi-local/internal/devicekeys"
)

/* ── HMAC 票：一台還沒註冊 passkey 的機器仍然動得了 ─────────────────────── */

// 這幾條守的是一個曾經真的存在的問題：Go 版一度不收 app 的 HMAC 票，於是
// **一台還沒註冊 passkey 的機器什麼都不讓做** —— 而使用者要註冊第一把
// passkey，得先有一台動得了的機器。那不是比較安全，是把人鎖在門外。
//
// 開關仍然在信任清單：註冊過任何一把金鑰之後，DelegateHMAC 就再也不會出現
// （那條在 devicekeys 的測試裡）。

func TestHmacTicketIsAcceptedWhenNoDeviceIsEnrolled(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.UnixMilli(1789000000000)
	token := mintForTest(t, key, "m-1", "exec", "ph-1", now)

	g := DeviceGate{Gate: emptyGateForTest(t), MachineID: "m-1", HmacKey: key, Now: func() time.Time { return now }}
	actionID, err := g.VerifyApproval("exec", "ph-1", token)
	if err != nil {
		t.Fatalf("還沒註冊 passkey 的機器被鎖住了：%v", err)
	}
	if actionID == "" {
		t.Fatal("沒有回 actionID —— 核准與稽核就對不起來")
	}
}

func TestHmacRefusalKeepsTheReason(t *testing.T) {
	// 「過期」的下一步是再按一次，「摘要不對」是我們兩邊算錯了東西。
	// 混成一句「票不對」的話，兩種人都會做錯事。
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.UnixMilli(1789000000000)
	token := mintForTest(t, key, "m-1", "exec", "ph-1", now)
	g := DeviceGate{Gate: emptyGateForTest(t), MachineID: "m-1", HmacKey: key, Now: func() time.Time { return now }}

	if _, err := g.VerifyApproval("exec", "另一個摘要", token); err == nil {
		t.Fatal("摘要不對卻放行")
	} else if !strings.Contains(err.Error(), "payload_mismatch") {
		t.Fatalf("理由不見了：%v", err)
	}

	late := DeviceGate{Gate: emptyGateForTest(t), MachineID: "m-1", HmacKey: key,
		Now: func() time.Time { return now.Add(10 * time.Minute) }}
	if _, err := late.VerifyApproval("exec", "ph-1", token); err == nil {
		t.Fatal("過期的票被放行")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("理由不見了：%v", err)
	}
}

func TestNoHmacKeyClosesTheDoorAndSaysWhatToDo(t *testing.T) {
	// 驗不了票還放行，等於整套核准不存在。失敗的方向要是關起來的那一邊，
	// 而且要說得出使用者真正能做的那一件事。
	g := DeviceGate{Gate: emptyGateForTest(t), MachineID: "m-1"} // 沒有 HmacKey
	_, err := g.VerifyApproval("exec", "ph-1", "any.token")
	if err == nil {
		t.Fatal("沒有金鑰卻放行")
	}
	if !strings.Contains(err.Error(), "重新配對") {
		t.Fatalf("沒說出下一步：%v", err)
	}
}

// emptyGateForTest 是一道「這台機器還沒註冊任何裝置」的閘 —— 也就是每一台
// 剛配對好的電腦的狀態。
func emptyGateForTest(t *testing.T) *devicekeys.Gate {
	t.Helper()
	return devicekeys.NewGate(devicekeys.GateOptions{
		Store:     devicekeys.Open(devicekeys.StoreOptions{File: filepath.Join(t.TempDir(), "devices.json"), MachineID: "m-1"}),
		MachineID: "m-1",
	})
}

// mintForTest 簽一張 app 會簽的那種 HMAC 票。**格式必須跟 approval.mjs 的
// mintApprovalToken 一致** —— 這裡自己組是為了不必在測試裡跑 node；
// internal/hmacapproval 那一支用的是 TS 真的簽出來的語料，兩邊一起綠才算數。
func mintForTest(t *testing.T, key []byte, machineID, tool, payloadHash string, now time.Time) string {
	t.Helper()
	body := map[string]any{
		"v": 1, "alg": "hmac", "invokeId": "inv-test", "machineId": machineID,
		"userId": nil, "sessionId": nil, "tool": tool, "payloadHash": payloadHash,
		"iat": now.UnixMilli(), "exp": now.UnixMilli() + 120_000, "nonce": "n-" + tool,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	claims := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(claims))
	return claims + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
