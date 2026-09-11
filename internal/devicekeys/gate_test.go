package devicekeys

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func gateAt(t *testing.T, dir string) (*Store, *Gate, time.Time) {
	t.Helper()
	now := time.UnixMilli(1_700_000_000_000)
	store := Open(StoreOptions{File: FileIn(dir), MachineID: testMachine, Now: func() time.Time { return now }})
	nonces := NewMemoryNonces(0)
	nonces.SetClock(func() time.Time { return now })
	return store, NewGate(GateOptions{Store: store, MachineID: testMachine, Nonces: nonces, Now: func() time.Time { return now }}), now
}

// 規則 2：**金鑰只從這台電腦上的信任清單來。**
//
// 雲端在票上自帶公鑰不可以有任何效果 —— 讀得到的話，被攻破的 app 只要附上
// 自己的公鑰就能簽任何東西，整個方案白做。
//
// 這條測試刻意做兩半：先證明那張票被擋（unknown_credential），再把同一把
// 金鑰**經過註冊**放進清單、用同一張票的等價物通過。只有前半的話，紅綠可能
// 是別的原因造成的（例如票根本壞了），那就什麼都沒證明。
func TestGateNeverTrustsKeysFromTheWire(t *testing.T) {
	dir := t.TempDir()
	store, gate, now := gateAt(t, dir)
	user := newCred(t, "user-laptop")
	attacker := newCred(t, "attacker")

	if _, _, err := store.Apply(enrollAdd(testMachine, user, "", now), nil); err != nil {
		t.Fatal(err)
	}

	// 攻擊者用自己的私鑰簽，並且把自己的公鑰塞在票裡（線路上多一個欄位）。
	ticket := deviceTicket(t, attacker, testMachine, "exec", "ph-1", "act-1", now)
	claimsB64, assertion, ok := ParseDeviceTicket(ticket)
	if !ok {
		t.Fatal("這張票本身應該是拆得開的，不然下面測不到重點")
	}
	body, _ := json.Marshal(map[string]any{
		"credentialId": assertion.CredentialID, "authenticatorData": assertion.AuthenticatorData,
		"clientDataJSON": assertion.ClientDataJSON, "signature": assertion.Signature,
		// ↓ 雲端自帶的公鑰。讀到它就等於整個方案沒有了。
		"publicKey": attacker.pub, "spki": attacker.pub,
	})
	withKey := TicketPrefix + claimsB64 + "." + b64urlEncode(body)

	d := gate.Require(withKey, Expect{Tool: "exec", PayloadHash: "ph-1"})
	if d.Allow || d.Reason != "unknown_credential" {
		t.Fatalf("線路上自帶的公鑰被讀到了：%+v", d)
	}

	// 同一把金鑰**走註冊那條路**進到清單之後就通 —— 證明上面紅的原因是
	// 「這把金鑰不在清單裡」，不是票壞了。
	req := enrollAdd(testMachine, attacker, "", now)
	by := user.signs(t, EnrollmentChallenge(req))
	if _, _, err := store.Apply(req, &by); err != nil {
		t.Fatalf("已信任的裝置簽的註冊該收：%v", err)
	}
	d2 := gate.Require(deviceTicket(t, attacker, testMachine, "exec", "ph-1", "act-2", now), Expect{Tool: "exec", PayloadHash: "ph-1"})
	if !d2.Allow || d2.ActionID != "act-2" || d2.CredentialID != "attacker" {
		t.Fatalf("進了清單之後應該通：%+v", d2)
	}
}

// 兩種票怎麼共存：還沒註冊裝置的機器 HMAC 照舊能用（不然更新的那一秒所有人
// 的機器一起停擺），註冊過之後 HMAC 一律拒絕。
func TestGateSwitchesToDeviceOnlyOnFirstEnrolment(t *testing.T) {
	dir := t.TempDir()
	store, gate, now := gateAt(t, dir)
	want := Expect{Tool: "exec", PayloadHash: "ph-1"}

	if d := gate.Require("some-hmac-token", want); !d.DelegateHMAC {
		t.Fatalf("還沒註冊裝置的機器要把 HMAC 票交回去驗：%+v", d)
	}
	if d := gate.Require("", want); d.Code != "approval_required" || d.DelegateHMAC {
		t.Fatalf("沒附票就是 approval_required：%+v", d)
	}

	if _, _, err := store.Apply(enrollAdd(testMachine, newCred(t, "laptop"), "", now), nil); err != nil {
		t.Fatal(err)
	}

	for _, token := range []string{"some-hmac-token", ""} {
		d := gate.Require(token, want)
		// 連「沒附票」都要說成這一句，否則使用者會一直重按一顆解決不了問題的
		// 允許鍵。
		if d.Allow || d.DelegateHMAC || d.Code != "device_approval_required" {
			t.Fatalf("註冊過裝置之後 HMAC 一律拒絕，卻得到 %+v", d)
		}
		if !strings.Contains(d.Message, "passkey") || !strings.Contains(d.Message, "exec") {
			t.Fatalf("那句話要說得出下一步：%q", d.Message)
		}
	}
}

// 票綁的是那一組 claims：換了 payload、換了工具、換了機器都對不上；
// 同一張票也不能用第二次。
func TestGateBindsTicketToTheAction(t *testing.T) {
	dir := t.TempDir()
	store, gate, now := gateAt(t, dir)
	cred := newCred(t, "laptop")
	if _, _, err := store.Apply(enrollAdd(testMachine, cred, "", now), nil); err != nil {
		t.Fatal(err)
	}

	ticket := deviceTicket(t, cred, testMachine, "exec", "ph-approved", "act-1", now)
	for _, tc := range []struct {
		name   string
		want   Expect
		reason string
	}{
		{"換掉指令", Expect{Tool: "exec", PayloadHash: "ph-evil"}, "payload_mismatch"},
		{"換掉工具", Expect{Tool: "writeFile", PayloadHash: "ph-approved"}, "wrong_tool"},
		{"換掉機器", Expect{MachineID: "m-other", Tool: "exec", PayloadHash: "ph-approved"}, "wrong_machine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if d := gate.Require(ticket, tc.want); d.Allow || d.Reason != tc.reason {
				t.Fatalf("應該是 %s，卻得到 %+v", tc.reason, d)
			}
		})
	}

	good := Expect{Tool: "exec", PayloadHash: "ph-approved"}
	if d := gate.Require(ticket, good); !d.Allow {
		t.Fatalf("對得上的那一次要放行：%+v", d)
	}
	if d := gate.Require(ticket, good); d.Allow || d.Reason != "replayed" {
		t.Fatalf("同一張票不能用第二次：%+v", d)
	}
}

// 壞掉的票不可以變成例外，也不可以被誤認成 HMAC 票。
func TestGateRefusesMalformedDeviceTicket(t *testing.T) {
	_, gate, _ := gateAt(t, t.TempDir())
	d := gate.Require(TicketPrefix+"沒有第二個點", Expect{Tool: "exec", PayloadHash: "ph"})
	if d.Allow || d.DelegateHMAC || d.Reason != "malformed_device_ticket" {
		t.Fatalf("壞掉的裝置票要當場說清楚：%+v", d)
	}
}

// 沒有信任清單的 build（Store 為 nil）＝ 這台機器不做裝置簽的核准，
// 每一張票都走 HMAC 那條路。不可以 panic。
func TestGateWithoutStoreFallsBackToHMAC(t *testing.T) {
	gate := NewGate(GateOptions{MachineID: testMachine})
	if d := gate.Require("some-hmac-token", Expect{Tool: "exec", PayloadHash: "ph"}); !d.DelegateHMAC {
		t.Fatalf("沒有信任清單就該交回 HMAC：%+v", d)
	}
	if d := gate.Require(TicketPrefix+"a.b", Expect{Tool: "exec", PayloadHash: "ph"}); d.Allow {
		t.Fatalf("沒有清單就沒有金鑰，裝置票不可能通：%+v", d)
	}
}
