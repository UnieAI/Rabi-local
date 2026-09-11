package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testdata 裡的每一份 manifest 都是 **TS 那一側真的簽出來的**
// （testdata/gen-manifests.ts，簽章輸入與編碼 import 自 daemon 與 app 共用的
// release-verify.ts），而且產生的時候已經先在 TS 的驗證器上得到預期答案。
// 所以這些測試回答的是一個具體的問題：Go 版跟 TS 版是不是同一個答案。

func read(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("讀不到 testdata/%s：%v（用 bun 跑 testdata/gen-manifests.ts 產生）", name, err)
	}
	return strings.TrimSpace(string(raw))
}

func testKey(t *testing.T) string  { t.Helper(); return read(t, "public-key-a.pem") }
func otherKey(t *testing.T) string { t.Helper(); return read(t, "public-key-b.pem") }

func TestGoodManifestVerifies(t *testing.T) {
	m, err := VerifyManifest(read(t, "good.manifest"), testKey(t))
	if err != nil {
		t.Fatalf("好的 manifest 應該過，卻是：%v", err)
	}
	if m.Version != "0.2.0" {
		t.Errorf("version = %q，預期 0.2.0", m.Version)
	}
	if !strings.Contains(m.Notes, "退回舊版") {
		t.Errorf("更新說明沒讀出來：%q", m.Notes)
	}
	a, ok := m.Artifacts["linux-x64"]
	if !ok {
		t.Fatalf("少了 linux-x64：%v", m.Artifacts)
	}
	if a.File != "ava-local-linux-x64" || a.Size <= 0 || len(a.SHA256) != 64 {
		t.Errorf("artifact 讀壞了：%+v", a)
	}
}

// 只改了更新說明的那一份必須被擋下來。使用者是**看著那段字**按下更新的：
// 一個「修了個小錯字」的說明可以被換成任何字，如果它不受簽章保護的話。
func TestTamperedNotesRejected(t *testing.T) {
	_, err := VerifyManifest(read(t, "tampered-notes.manifest"), testKey(t))
	if GateOf(err) != GateSignature {
		t.Fatalf("改過 changelog 的 manifest 應該卡在簽章這一關，卻是 gate=%q err=%v", GateOf(err), err)
	}
}

// 只改了 sha256 —— 那是掉包位元組的唯一辦法，所以它一定要驗不過。
func TestTamperedSHA256Rejected(t *testing.T) {
	_, err := VerifyManifest(read(t, "tampered-sha256.manifest"), testKey(t))
	if GateOf(err) != GateSignature {
		t.Fatalf("改過 sha256 的 manifest 應該卡在簽章這一關，卻是 gate=%q err=%v", GateOf(err), err)
	}
}

// 形狀完全正確、欄位全對，就是**不是我們的私鑰簽的**。
func TestOtherKeySignatureRejected(t *testing.T) {
	token := read(t, "other-key.manifest")
	_, err := VerifyManifest(token, testKey(t))
	if GateOf(err) != GateSignature {
		t.Fatalf("別人的鑰匙簽的應該卡在簽章這一關，卻是 gate=%q err=%v", GateOf(err), err)
	}
	if !strings.Contains(err.Error(), "不是 UnieAI 發的") {
		t.Errorf("訊息要說得出發生什麼事，卻是：%v", err)
	}
	// 反過來也要成立：同一份 token 用 B 的公鑰就驗得過 —— 證明擋下它的是
	// 鑰匙不對，不是那份 token 本身有什麼毛病。
	if _, err := VerifyManifest(token, otherKey(t)); err != nil {
		t.Fatalf("用 B 的公鑰應該驗得過：%v", err)
	}
}

// 測試用的 manifest 不該被**正式的**公鑰放行 —— 不然這整組測試什麼都沒測到。
func TestTestdataIsNotSignedByProductionKey(t *testing.T) {
	if _, err := VerifyManifest(read(t, "good.manifest"), PublicKeyPEM); err == nil {
		t.Fatal("testdata 竟然被正式公鑰驗過了：那表示測試金鑰外洩或公鑰被換掉了")
	}
}

func TestMalformedTokens(t *testing.T) {
	good := read(t, "good.manifest")
	parts := strings.Split(good, ".")
	cases := map[string]struct {
		token string
		gate  Gate
	}{
		"空字串":               {"", GateFormat},
		"只有兩段":              {parts[0] + "." + parts[1], GateFormat},
		"前綴不對":              {"avalic." + parts[1] + "." + parts[2], GateFormat},
		"payload 不是 base64": {parts[0] + ".@@@." + parts[2], GateEncoding},
		"簽章長度不對":            {parts[0] + "." + parts[1] + ".AAAA", GateSignature},
		"公鑰壞掉":              {good, GateSignature},
	}
	for name, c := range cases {
		key := testKey(t)
		if name == "公鑰壞掉" {
			key = "不是 PEM"
		}
		if _, err := VerifyManifest(c.token, key); GateOf(err) != c.gate {
			t.Errorf("%s：gate=%q，預期 %q（err=%v）", name, GateOf(err), c.gate, err)
		}
	}
}

// 簽章對、但欄位不合法的那一份要卡在 fields，不能靜靜地被接受。
func TestFieldValidation(t *testing.T) {
	// 這一組測的是「簽章對，但欄位不合法」，跟是誰簽的無關，所以現場產一把
	// 鑰匙、真的簽下去 —— 半路塞進解析器測不到前面那一關有沒有先跑。
	pub, sign := fieldTestSigner(t)
	for name, payload := range map[string]string{
		"v 不是 1":        `{"v":2,"version":"0.2.0","released":"x","notes":"n","artifacts":{"linux-x64":{"file":"f","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		"版本形狀不對":        `{"v":1,"version":"0.2","released":"x","notes":"n","artifacts":{"linux-x64":{"file":"f","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		"沒有 notes":      `{"v":1,"version":"0.2.0","released":"x","artifacts":{"linux-x64":{"file":"f","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		"notes 全空白":     `{"v":1,"version":"0.2.0","released":"x","notes":"   ","artifacts":{"linux-x64":{"file":"f","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		"沒有任何檔案":        `{"v":1,"version":"0.2.0","released":"x","notes":"n","artifacts":{}}`,
		"檔名有路徑":         `{"v":1,"version":"0.2.0","released":"x","notes":"n","artifacts":{"linux-x64":{"file":"../../etc/passwd","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		"size 是小數":      `{"v":1,"version":"0.2.0","released":"x","notes":"n","artifacts":{"linux-x64":{"file":"f","size":1.5,"sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		"size 是 0":      `{"v":1,"version":"0.2.0","released":"x","notes":"n","artifacts":{"linux-x64":{"file":"f","size":0,"sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		"sha256 不是 hex": `{"v":1,"version":"0.2.0","released":"x","notes":"n","artifacts":{"linux-x64":{"file":"f","size":1,"sha256":"zz"}}}`,
	} {
		if _, err := VerifyManifest(sign(payload), pub); GateOf(err) != GateFields {
			t.Errorf("%s：gate=%q，預期 fields（err=%v）", name, GateOf(err), err)
		}
	}
	// 對照組：同一條路徑上，合法的 payload 要過。
	ok := `{"v":1,"version":"0.2.0","released":"x","notes":"n","artifacts":{"linux-x64":{"file":"f","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}}}`
	if _, err := VerifyManifest(sign(ok), pub); err != nil {
		t.Errorf("對照組應該過：%v", err)
	}
}

func TestVerifyBytes(t *testing.T) {
	m, err := VerifyManifest(read(t, "good.manifest"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	a := m.Artifacts["linux-x64"]
	good, err := os.ReadFile(filepath.Join("testdata", "artifact-linux-x64"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBytes(good, a); err != nil {
		t.Fatalf("真的那一份應該過：%v", err)
	}
	if err := VerifyBytes(good[:len(good)-1], a); GateOf(err) != GateSize {
		t.Errorf("少一個 byte 應該卡在 size：gate=%q err=%v", GateOf(err), err)
	}
	// 大小一樣、內容不一樣 —— 這就是 sha256 存在的理由。
	swapped := append([]byte(nil), good...)
	swapped[len(swapped)-2] ^= 0x20
	err = VerifyBytes(swapped, a)
	if GateOf(err) != GateSHA256 {
		t.Errorf("改一個 byte 應該卡在 sha256：gate=%q err=%v", GateOf(err), err)
	}
	if !strings.Contains(err.Error(), "sha256 不符") {
		t.Errorf("訊息要說得出是哪一關：%v", err)
	}
}

func TestCompareVersions(t *testing.T) {
	newer := [][2]string{
		{"0.2.0", "0.1.9"},
		{"0.2.0", "0.2.0-beta.1"}, // 正式版比預發布新
		{"1.0.0", "0.99.99"},
		{"0.2.1", "0.2.0"},
		{"0.2.0-beta.2", "0.2.0-beta.1"},
	}
	for _, c := range newer {
		if !IsNewerVersion(c[0], c[1]) {
			t.Errorf("%s 應該比 %s 新", c[0], c[1])
		}
		if IsNewerVersion(c[1], c[0]) {
			t.Errorf("%s 不該比 %s 新", c[1], c[0])
		}
	}
	if IsNewerVersion("0.2.0", "0.2.0") {
		t.Error("一樣的版本不該算新")
	}
	if CompareVersions("0.2.0", "0.2.0") != 0 {
		t.Error("一樣的版本應該相等")
	}
}

func TestArtifactKey(t *testing.T) {
	for _, c := range []struct{ goos, goarch, want string }{
		{"linux", "amd64", "linux-x64"}, // Go 叫 amd64，manifest 是 node 的名字 x64
		{"darwin", "arm64", "darwin-arm64"},
		{"windows", "amd64", "windows-x64"},
	} {
		if got := ArtifactKey(c.goos, c.goarch); got != c.want {
			t.Errorf("ArtifactKey(%s,%s) = %s，預期 %s", c.goos, c.goarch, got, c.want)
		}
	}
}

// fieldTestSigner 現場產一把只給這次測試用的鑰匙，並回傳「把任意 payload 簽成
// 一份 token」的函式。簽的方式跟 TS 那一側同一句話：base64url(payload) 的
// UTF-8 位元組就是簽章輸入（見 SigningInput）。
func fieldTestSigner(t *testing.T) (string, func(payload string) string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return pubPEM, func(payload string) string {
		part := base64.RawURLEncoding.EncodeToString([]byte(payload))
		sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, SigningInput(part)))
		return TokenPrefix + "." + part + "." + sig
	}
}
