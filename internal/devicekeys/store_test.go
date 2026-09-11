package devicekeys

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const testMachine = "m-dev"

func openStore(t *testing.T, dir string) *Store {
	t.Helper()
	return Open(StoreOptions{File: FileIn(dir), MachineID: testMachine, Now: func() time.Time { return time.UnixMilli(1_700_000_000_000) }})
}

// 第一把是在那台電腦上當面確認的（配對的那一刻使用者人就在電腦前），而且
// **存得住** —— 信任清單如果跟設定寫在同一個檔案，一次 token 輪替就會把它
// 洗掉，症狀是這台機器安靜地退回「雲端說了算」。
func TestFirstKeyIsLocalThenPersists(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir)
	laptop := newCred(t, "laptop")

	if s.DeviceOnly() {
		t.Fatal("一把都還沒有就說自己是 device-only")
	}
	op, id, err := s.Apply(enrollAdd(testMachine, laptop, "roy 的筆電", time.UnixMilli(1_700_000_000_000)), nil)
	if err != nil || op != "add" || id != "laptop" {
		t.Fatalf("第一把應該收得下：%v %v %v", op, id, err)
	}
	if !s.DeviceOnly() || s.DeviceOnlySince() == "" {
		t.Fatal("有金鑰之後就該是 device-only")
	}

	again := openStore(t, dir) // ＝ 重開 daemon
	if !again.DeviceOnly() || len(again.List()) != 1 {
		t.Fatalf("重開之後信任清單不見了：%+v", again.List())
	}
	if again.List()[0].Label == nil || *again.List()[0].Label != "roy 的筆電" {
		t.Fatalf("label 沒存住：%+v", again.List()[0])
	}
	if _, ok := again.Keys()["laptop"]; !ok {
		t.Fatal("重開之後那把金鑰查不到")
	}
}

// 第一把之後，本機確認不再是捷徑；雲端自產一把自己簽也進不來；只有已經信任
// 的裝置簽得動。（規則本身由 vectors 釘住，這裡釘的是 Store 真的把它接上了。）
func TestSecondKeyNeedsATrustedSigner(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir)
	now := time.UnixMilli(1_700_000_000_000)
	laptop, phone, attacker := newCred(t, "laptop"), newCred(t, "phone"), newCred(t, "attacker")

	if _, _, err := s.Apply(enrollAdd(testMachine, laptop, "", now), nil); err != nil {
		t.Fatal(err)
	}

	// 沒有簽 —— 有金鑰之後本機確認不算數。
	// 兩條規則都會擋（Store 在有金鑰之後根本不宣稱「本機確認」，
	// VerifyEnrollment 自己也擋一次），挑一個特定的理由會把這條測試綁在檢查
	// 順序上，而順序不是它要守的東西 —— 它要守的是「加不進去」。
	if _, _, err := s.Apply(enrollAdd(testMachine, phone, "", now), nil); err == nil {
		t.Fatal("本機確認在第一把之後就該失效")
	}
	// 雲端自產一把、自己簽自己進來
	selfSigned := enrollAdd(testMachine, attacker, "", now)
	by := attacker.signs(t, EnrollmentChallenge(selfSigned))
	if _, _, err := s.Apply(selfSigned, &by); !errors.Is(err, ReasonSignerNotTrusted) {
		t.Fatalf("雲端自簽不該進得來，卻得到 %v", err)
	}
	if len(s.List()) != 1 {
		t.Fatalf("被拒絕的註冊不可以留下痕跡：%+v", s.List())
	}

	// 已經信任的筆電簽過的第二把算數
	req := enrollAdd(testMachine, phone, "手機", now)
	signed := laptop.signs(t, EnrollmentChallenge(req))
	if _, _, err := s.Apply(req, &signed); err != nil {
		t.Fatalf("已信任的裝置簽的第二把該收：%v", err)
	}
	if len(s.List()) != 2 {
		t.Fatalf("第二把沒進去：%+v", s.List())
	}

	// 撤到剩一把可以，撤到零把不行 —— 零把就落回本機確認，等於任何能在那台
	// 機器上跑程式的人都能接管。
	rm := enrollRemove(testMachine, phone.id, now)
	sig := laptop.signs(t, EnrollmentChallenge(rm))
	if _, _, err := s.Apply(rm, &sig); err != nil {
		t.Fatalf("撤掉手機該可以：%v", err)
	}
	last := enrollRemove(testMachine, laptop.id, now)
	sig2 := laptop.signs(t, EnrollmentChallenge(last))
	if _, _, err := s.Apply(last, &sig2); !errors.Is(err, ReasonWouldLeaveNone) {
		t.Fatalf("撤到一把不剩不該准，卻得到 %v", err)
	}
}

// 信任清單讀不得＝停擺，**不是安靜地退回 HMAC**（那正是攻擊者要的降級）。
func TestUnsafeStoreStallsInsteadOfDowngrading(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 沒有這種權限位元")
	}
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, file string)
	}{
		{"別的帳號寫得了", func(t *testing.T, file string) {
			if err := os.Chmod(file, 0o666); err != nil {
				t.Fatal(err)
			}
		}},
		{"JSON 被弄壞", func(t *testing.T, file string) {
			if err := os.WriteFile(file, []byte("{ 不是 JSON"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := openStore(t, dir)
			if _, _, err := s.Apply(enrollAdd(testMachine, newCred(t, "laptop"), "", time.UnixMilli(1_700_000_000_000)), nil); err != nil {
				t.Fatal(err)
			}
			tc.damage(t, FileIn(dir))

			broken := openStore(t, dir)
			if broken.Unsafe() == "" {
				t.Fatal("清單不可信的時候要說得出原因")
			}
			// 三個都要空 —— 只要有一個漏了，某條路就會以為這台機器沒註冊過裝置。
			if len(broken.List()) != 0 || len(broken.Keys()) != 0 || broken.DeviceOnly() {
				t.Fatal("不可信的清單不可以被當成證據")
			}
			if _, _, err := broken.Apply(enrollAdd(testMachine, newCred(t, "x"), "", time.Now()), nil); !errors.Is(err, ReasonStoreUnsafe) {
				t.Fatalf("不可信的時候不該收註冊，卻得到 %v", err)
			}

			// 最要緊的一條：閘門不可以因此變回「HMAC 也收」。
			g := NewGate(GateOptions{Store: broken, MachineID: testMachine})
			d := g.Require("some-hmac-token", Expect{Tool: "exec", PayloadHash: "ph"})
			if d.Allow || d.DelegateHMAC || d.Code != "device_store_unsafe" {
				t.Fatalf("清單不可信時必須停擺，卻得到 %+v", d)
			}
		})
	}
}

// 信任清單是私人的：0600。別的帳號讀得到不致命（都是公鑰），寫得到才是。
// 寫得到的那一刻它就不再是證據，所以乾脆不要讓它變成可寫的。
func TestStoreFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 沒有這種權限位元")
	}
	dir := t.TempDir()
	s := openStore(t, dir)
	if _, _, err := s.Apply(enrollAdd(testMachine, newCred(t, "laptop"), "", time.UnixMilli(1_700_000_000_000)), nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(FileIn(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("信任清單的權限是 %o，應該是 600", info.Mode().Perm())
	}
	// 暫存檔不可以留在使用者的資料夾裡
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) != "" && len(e.Name()) > len("devices.json") {
			t.Fatalf("寫完之後留下垃圾：%s", e.Name())
		}
	}
}

// 存不下來就**不可以**假裝成功：記憶體裡算數、重開就沒了的信任清單，會讓
// 使用者以為自己已經在 device-only 了。
func TestWriteFailureIsNotSilentlyAccepted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 寫得進唯讀目錄，測不到")
	}
	dir := t.TempDir()
	s := openStore(t, dir)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, _, err := s.Apply(enrollAdd(testMachine, newCred(t, "laptop"), "", time.UnixMilli(1_700_000_000_000)), nil)
	if !errors.Is(err, ReasonStoreWriteFailed) {
		t.Fatalf("寫不進去卻回 %v", err)
	}
	if s.DeviceOnly() || len(s.List()) != 0 {
		t.Fatal("寫不進去的金鑰不可以留在記憶體裡算數")
	}
}

// 欄位型別不對**只跳過那一筆**，不是整台機器停擺 —— TS 那邊就是這樣，而
// 「比 TS 嚴格」在這裡不是安全，是分歧：同一個檔案兩個 daemon 一個能用、
// 一個停擺。（語法壞掉才停擺，見上面那條。）
func TestBadFieldTypesSkipTheEntryInsteadOfStalling(t *testing.T) {
	dir := t.TempDir()
	good := newCred(t, "good")
	raw := `{"v":1,"devices":[
		{"credentialId":"good","publicKey":` + jsonQuote(good.pub) + `,"label":"筆電","addedAt":"2026-01-01T00:00:00.000Z"},
		{"credentialId":"no-key"},
		{"credentialId":"bad-key","publicKey":123},
		{"credentialId":"good","publicKey":` + jsonQuote(good.pub) + `},
		{"publicKey":` + jsonQuote(good.pub) + `}
	],"deviceOnlySince":null}`
	if err := os.WriteFile(FileIn(dir), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	s := openStore(t, dir)
	if s.Unsafe() != "" {
		t.Fatalf("型別不對不該停擺：%s", s.Unsafe())
	}
	if len(s.List()) != 1 || s.List()[0].CredentialID != "good" {
		t.Fatalf("該留下一把（其餘跳過），卻是 %+v", s.List())
	}
	// deviceOnlySince 是 null → 退回第一把的時間
	if s.DeviceOnlySince() != "2026-01-01T00:00:00.000Z" {
		t.Fatalf("deviceOnlySince 該退回第一把的時間，卻是 %q", s.DeviceOnlySince())
	}
	if !s.DeviceOnly() {
		t.Fatal("有一把就是 device-only")
	}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
