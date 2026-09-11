package devicekeys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// Store 是這台電腦信任哪幾把裝置公鑰，以及它們存在哪。
//
// # 這份清單就是那條界線
//
// 「雲端偽造不出核准，因為它沒有私鑰」這句話成立的唯一理由是**這份清單不由
// 雲端決定**。所以這個型別只做兩件事：
//
//  1. 把清單存在使用者自己的電腦上（雲端寫不到的地方）；
//  2. 每一次異動都交給 VerifyEnrollment 判斷 —— 規則一條都不在這裡重寫。
//
// # 為什麼另開一個檔案，不寫進 config.json
//
// config.json 是 daemon **自己會整份覆寫**的檔案（配對、換 token 都寫）。
// 信任清單被一次 token 輪替洗掉的症狀不是「壞掉」，是**這台機器安靜地退回
// 只收 HMAC 票的世界** —— 也就是雲端又說了算，而畫面上什麼都不會說。
//
// # 「從此只收裝置簽的票」怎麼開啟
//
// 這份清單上**有任何一把金鑰**，這台機器就進入 device-only：HMAC 票一律
// 拒絕（見 gate.go）。不另外存一個開關，因為兩個真相遲早會不一致，而不一致
// 的那一邊會是「以為自己受保護、其實沒有」。
//
// 這個狀態**回得去，但只有人回得去**：使用者在自己電腦上刪掉這個檔案就退回
// HMAC（他本來就對自己的電腦有完全的權力）。雲端做不到 —— 它沒有辦法寫這台
// 電腦上的任何一個檔案，VerifyEnrollment 也不准撤到一把不剩。
type Store struct {
	mu        sync.Mutex
	file      string
	machineID string
	now       func() time.Time
	verifier  SignatureVerifier
	logf      func(format string, args ...any)

	devices         []TrustedDevice
	deviceOnlySince string
	unsafe          string
}

// TrustedDevice 是一把使用者註冊過的裝置金鑰。
// **只有公開資訊** —— 私鑰從來沒有到過這裡。
type TrustedDevice struct {
	CredentialID string `json:"credentialId"`
	// PublicKey 是 SPKI，存成 PEM。
	PublicKey string `json:"publicKey"`
	// Label 是使用者給它的名字；沒取名就是 JSON null。
	Label   *string `json:"label"`
	AddedAt string  `json:"addedAt"`
}

// maxDevices 是一台機器最多幾把。
//
// 不是安全限制，是**止血**：一個壞掉的呼叫端重試一千次，會把這個檔案灌成
// 一千把金鑰，而使用者在畫面上分不出哪一把是他自己的手機。
const maxDevices = 32

// StoreOptions 是打開一份信任清單要給的東西。
type StoreOptions struct {
	// File 是清單檔的完整路徑（見 FileIn）。
	File string
	// MachineID 是這台機器的身分；註冊請求上的 machineId 要跟它一致。
	MachineID string
	// Now 零值就用系統時鐘。
	Now func() time.Time
	// Verifier 不給就用 StdSignatureVerifier。
	Verifier SignatureVerifier
	// Logf 不給就不記錄。
	Logf func(format string, args ...any)
}

// FileIn 回傳信任清單在某個設定目錄底下的檔名。
//
// 獨立一個檔案是刻意的，見 Store 的說明。
func FileIn(dir string) string { return filepath.Join(dir, "devices.json") }

type deviceFile struct {
	V               int             `json:"v"`
	Devices         []TrustedDevice `json:"devices"`
	DeviceOnlySince *string         `json:"deviceOnlySince"`
}

// Open 讀出這台電腦的信任清單。**永遠回得出一個 Store**，不會是 nil ——
// 讀不得的時候它的 Unsafe() 非空，而呼叫端看到那個就要讓整台機器的核准停擺
// （不是忽略）。
func Open(opts StoreOptions) *Store {
	s := &Store{
		file:      opts.File,
		machineID: opts.MachineID,
		now:       opts.Now,
		verifier:  opts.Verifier,
		logf:      opts.Logf,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.verifier == nil {
		s.verifier = StdSignatureVerifier{}
	}
	devices, since, unsafe := loadDeviceFile(opts.File)
	s.devices, s.deviceOnlySince, s.unsafe = devices, since, unsafe
	if unsafe != "" && s.logf != nil {
		s.logf("[ava-local] 裝置金鑰檔不安全：%s", unsafe)
	}
	return s
}

// loadDeviceFile 讀檔。**永遠回得出東西**，但權限不對或 JSON 壞掉會回 unsafe。
func loadDeviceFile(file string) (devices []TrustedDevice, since string, unsafe string) {
	info, err := os.Stat(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ""
	}
	if err == nil && runtime.GOOS != "windows" {
		mode := info.Mode().Perm()
		// 別的帳號寫得了這個檔案，清單就不再是證據（他可以加一把自己的）。
		if mode&0o022 != 0 {
			return nil, "", fmt.Sprintf(
				"%s 是其他帳號可寫的（權限 %s）—— 能寫這個檔案的人就能把自己的金鑰加進你的信任清單。請 chmod 600 之後重開 daemon。",
				file, strconv.FormatUint(uint64(mode), 8))
		}
	}

	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, "", fmt.Sprintf("%s 讀不到：%s", file, err)
	}
	// 壞掉的 JSON **不可以**被當成「沒有金鑰」：那就是一條把 device-only 關掉
	// 的路（把檔案弄壞就好）。所以這也算 unsafe，讓它大聲停擺。
	//
	// 反過來說，**只有語法壞掉才算 unsafe**：欄位型別不對（devices 是個物件、
	// publicKey 是數字）在 TS 那邊是「跳過這一筆」而不是停擺，所以這裡也用
	// 一樣的寬鬆讀法，而不是 unmarshal 到結構上 —— 那會讓一個手改壞的欄位
	// 變成整台機器停擺，跟 TS 版不一樣。
	root, ok := parseJSON(raw)
	if !ok {
		return nil, "", fmt.Sprintf("%s 不是合法的 JSON", file)
	}

	epoch := time.UnixMilli(0).UTC().Format(isoLayout)
	list, _ := jsField(root, "devices").([]any)
	seen := map[string]bool{}
	for _, entry := range list {
		credentialID := jsToString(jsField(entry, "credentialId"))
		pem, keyOK := pemFrom(jsToString(jsField(entry, "publicKey")))
		if credentialID == "" || !keyOK || seen[credentialID] {
			continue
		}
		seen[credentialID] = true
		var label *string
		if l, isStr := jsString(entry, "label"); isStr {
			label = &l
		}
		addedAt, isStr := jsString(entry, "addedAt")
		if !isStr {
			addedAt = epoch
		}
		devices = append(devices, TrustedDevice{CredentialID: credentialID, PublicKey: pem, Label: label, AddedAt: addedAt})
	}
	if s, isStr := jsString(root, "deviceOnlySince"); isStr {
		since = s
	} else if len(devices) > 0 {
		since = devices[0].AddedAt
	}
	return devices, since, ""
}

const isoLayout = "2006-01-02T15:04:05.000Z"

// List 是信任清單。權限不對的時候是空的 —— 但 Unsafe() 會說出原因。
func (s *Store) List() []TrustedDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unsafe != "" {
		return nil
	}
	out := make([]TrustedDevice, len(s.devices))
	copy(out, s.devices)
	return out
}

// Keys 給 VerifyDeviceApproval / VerifyEnrollment 用的 credentialId → 公鑰。
//
// **這是整條路上唯一的金鑰來源。** 線路上帶什麼公鑰都不可以進到這裡。
func (s *Store) Keys() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keysLocked()
}

func (s *Store) keysLocked() map[string]string {
	if s.unsafe != "" {
		return map[string]string{}
	}
	out := make(map[string]string, len(s.devices))
	for _, d := range s.devices {
		out[d.CredentialID] = d.PublicKey
	}
	return out
}

// DeviceOnly 有金鑰＝這台機器從此只收裝置簽的票。
func (s *Store) DeviceOnly() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unsafe == "" && len(s.devices) > 0
}

// DeviceOnlySince 第一把是什麼時候進來的（回報用；真相仍然是 List() 有沒有
// 東西）。
func (s *Store) DeviceOnlySince() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unsafe != "" {
		return ""
	}
	return s.deviceOnlySince
}

// Unsafe 是檔案權限不對之類的問題。非空時，這台機器的核准全部停擺。
func (s *Store) Unsafe() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unsafe
}

// Apply 註冊或撤銷一把金鑰。規則全部由 VerifyEnrollment 決定。
//
// by 為 nil 代表本機當面確認（只有第一把用得到，見 enrollment.go）。
func (s *Store) Apply(enrollB64 string, by *Assertion) (op string, credentialID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unsafe != "" {
		return "", "", ReasonStoreUnsafe
	}

	req, verr := VerifyEnrollment(enrollB64, by, EnrollmentDeps{
		MachineID: s.machineID,
		Keys:      s.keysLocked(),
		// **第一把才有這個。**「本機當面確認」的具體意義是：這台機器是使用者
		// 親手配對的（他那時人就在電腦前），而清單上一把都還沒有。
		// VerifyEnrollment 自己也會再檢查一次，所以這一行放寬不了任何規則。
		LocalConfirm: len(s.devices) == 0,
		Now:          s.now(),
		Verifier:     s.verifier,
	})
	if verr != nil {
		return "", "", verr
	}

	next := make([]TrustedDevice, 0, len(s.devices)+1)
	for _, d := range s.devices {
		if d.CredentialID != req.CredentialID {
			next = append(next, d)
		}
	}
	nextSince := s.deviceOnlySince

	if req.Op == "add" {
		if len(next) >= maxDevices {
			return "", "", ReasonTooManyDevices
		}
		pem, ok := pemFrom(req.PublicKey)
		if !ok {
			return "", "", ReasonBadPublicKey
		}
		addedAt := s.now().UTC().Format(isoLayout)
		var label *string
		if req.Label != "" {
			l := truncateUTF16(req.Label, 120)
			label = &l
		}
		next = append(next, TrustedDevice{
			CredentialID: req.CredentialID,
			PublicKey:    pem,
			Label:        label,
			AddedAt:      addedAt,
		})
		if nextSince == "" {
			nextSince = addedAt
		}
	}

	if err := saveDeviceFile(s.file, next, nextSince); err != nil {
		// 存不下來就**不可以**假裝成功：記憶體裡算數、重開就沒了的信任清單，
		// 會讓使用者以為自己已經在 device-only 了。
		if s.logf != nil {
			s.logf("[ava-local] 裝置金鑰寫入失敗：%s", err)
		}
		return "", "", ReasonStoreWriteFailed
	}
	s.devices, s.deviceOnlySince = next, nextSince
	return req.Op, req.CredentialID, nil
}

func saveDeviceFile(file string, devices []TrustedDevice, since string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	if devices == nil {
		devices = []TrustedDevice{}
	}
	var sincePtr *string
	if since != "" {
		sincePtr = &since
	}
	raw, err := json.MarshalIndent(deviceFile{V: 1, Devices: devices, DeviceOnlySince: sincePtr}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	// 先寫暫存檔再 rename：這個檔案掉一半的後果是「信任清單不見了」，而使用者
	// 看到的是他的核准突然全部失效。rename 在同一個目錄裡是原子的。
	// 暫存檔名帶亂數 —— 固定名字的話，兩個併行的寫入會交錯成一個各半的檔案。
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := file + ".tmp-" + hex.EncodeToString(suffix)
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil && runtime.GOOS != "windows" {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, file); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// pemFrom 把呼叫端給的公鑰正規化成 PEM，順便確認它真的是一把金鑰。
//
// 瀏覽器的 getPublicKey() 回的是 SPKI 的位元組，所以送過來的多半是 base64
// （或 base64url）的 DER；PEM 也收，測試與 CLI 比較好寫。
func pemFrom(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	text := s
	if !strings.Contains(s, "-----BEGIN") {
		der := b64urlDecode(s)
		body := base64.StdEncoding.EncodeToString(der)
		var lines []string
		for len(body) > 64 {
			lines = append(lines, body[:64])
			body = body[64:]
		}
		if body != "" {
			lines = append(lines, body)
		}
		text = "-----BEGIN PUBLIC KEY-----\n" + strings.Join(lines, "\n") + "\n-----END PUBLIC KEY-----\n"
	}
	if _, err := parsePublicKey(text); err != nil {
		return "", false
	}
	return text, true
}

// truncateUTF16 照 JS 的 String.prototype.slice(0, n) 截斷（UTF-16 碼元）。
func truncateUTF16(s string, n int) string {
	units := utf16.Encode([]rune(s))
	if len(units) <= n {
		return s
	}
	return string(utf16.Decode(units[:n]))
}
