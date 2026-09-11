package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// TokenPrefix 是 manifest 的第一段，對應 TS 的 AVA_RELEASE_TOKEN_PREFIX。
const TokenPrefix = "avarel"

// Gate 是「沒過的是哪一關」。
//
// 驗不過的時候只說一句「驗證失敗」，使用者與客服都沒有下一步可走：簽章不對
// 是**有人在中間動手腳**（要報警），sha256 不對多半是下載壞了（重試就好），
// 版本不對則根本不該重試。所以每個失敗都帶著關卡名字回來。
type Gate string

const (
	GateNone      Gate = ""
	GateFormat    Gate = "format"    // 根本不是一份 manifest
	GateEncoding  Gate = "encoding"  // base64 / JSON 壞了
	GateSignature Gate = "signature" // 不是我們的私鑰簽的
	GateFields    Gate = "fields"    // 簽章對，但欄位不合法
	GateSize      Gate = "size"      // 下載回來的大小跟 manifest 不符
	GateSHA256    Gate = "sha256"    // 下載回來的內容跟 manifest 不符
	GateVersion   Gate = "version"   // 版本比較不讓它裝
	GatePlatform  Gate = "platform"  // 這個版本沒有這台機器的檔案
)

// VerifyError 是「驗不過」。它是一個錯誤，但說得出是哪一關。
type VerifyError struct {
	Gate   Gate
	Reason string
}

func (e *VerifyError) Error() string { return e.Reason }

func gateErr(g Gate, format string, a ...any) *VerifyError {
	return &VerifyError{Gate: g, Reason: fmt.Sprintf(format, a...)}
}

// GateOf 從錯誤裡取出關卡名字；不是驗證錯誤就回 GateNone。
func GateOf(err error) Gate {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve.Gate
	}
	return GateNone
}

// Artifact 是某一個平台的檔案。下載網址由版本與 File 組出來。
type Artifact struct {
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest 是一份發布資訊。欄位與 TS 的 ReleaseManifest 一對一。
type Manifest struct {
	V        int    `json:"v"`
	Version  string `json:"version"`
	Released string `json:"released"`
	// Notes 是給使用者看的更新說明（繁體中文，純文字，一行一項）。
	// **必填**，而且跟版本、跟每個檔案的 sha256 一起被同一個簽章蓋住。
	Notes     string              `json:"notes"`
	Artifacts map[string]Artifact `json:"artifacts"`
	// MinVersion：低於這個版本的 daemon 不要自動跳過去（需要手動重裝）。
	MinVersion string `json:"minVersion,omitempty"`
	Channel    string `json:"channel,omitempty"`
}

var (
	reSHA256    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reSafeFile  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)
	reVersion   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]{1,32})?$`)
	rePlatform  = regexp.MustCompile(`^[a-z0-9-]{3,24}$`)
	reChannelID = regexp.MustCompile(`^[a-z0-9-]{1,16}$`)
)

// ParsePublicKey 把 SPKI PEM 轉成 Ed25519 公鑰。
func ParsePublicKey(pemText string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, errors.New("公鑰不是 PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("公鑰解不開：%w", err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("公鑰不是 Ed25519")
	}
	return ed, nil
}

// decodeBase64URL 跟 TS 的 base64UrlToBuffer 一樣寬容：補回 padding，
// 也吃得下標準字母表（+ /）—— 簽的那一側換過工具的話不該變成「驗不過」。
func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(s, "+", "-"), "/", "_"), "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// SigningInput 是簽章蓋住的那串位元組。簽跟驗只能有這一個答案，
// 所以它跟 TS 的 releaseSigningInput 必須是同一句話：payload 那一段的 UTF-8。
func SigningInput(payloadPart string) []byte { return []byte(payloadPart) }

// VerifyManifest 驗一份 manifest。
//
// **先驗簽章，再看內容** —— 反過來的話，一份沒驗過的 JSON 已經被我們的
// 解析器讀過一遍了。回傳的錯誤一定是 *VerifyError，用 GateOf 問是哪一關。
func VerifyManifest(token string, publicKeyPEM string) (*Manifest, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || parts[0] != TokenPrefix || parts[1] == "" || parts[2] == "" {
		return nil, gateErr(GateFormat, "格式不是 release manifest")
	}
	payloadPart, signaturePart := parts[1], parts[2]

	signature, err := decodeBase64URL(signaturePart)
	if err != nil {
		return nil, gateErr(GateEncoding, "編碼壞了")
	}
	payloadJSON, err := decodeBase64URL(payloadPart)
	if err != nil {
		return nil, gateErr(GateEncoding, "編碼壞了")
	}

	key, err := ParsePublicKey(publicKeyPEM)
	// 換過的公鑰格式、長度不對的簽章 —— 都是「驗不過」，不是例外。
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key, SigningInput(payloadPart), signature) {
		return nil, gateErr(GateSignature, "簽章不對：這份更新不是 UnieAI 發的")
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payloadJSON, &raw); err != nil {
		return nil, gateErr(GateEncoding, "編碼壞了")
	}
	m, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func parseManifest(raw map[string]json.RawMessage) (*Manifest, error) {
	bad := func(why string) (*Manifest, error) {
		return nil, gateErr(GateFields, "manifest 欄位不合法（%s）", why)
	}
	var m Manifest
	if err := json.Unmarshal(mustRaw(raw["v"]), &m.V); err != nil || m.V != 1 {
		return bad("v")
	}
	if err := json.Unmarshal(mustRaw(raw["version"]), &m.Version); err != nil || !reVersion.MatchString(m.Version) {
		return bad("version")
	}
	if err := json.Unmarshal(mustRaw(raw["released"]), &m.Released); err != nil || m.Released == "" {
		return bad("released")
	}
	// changelog 是必要欄位。沒有它，使用者是在對一個看不見內容的東西按同意。
	if err := json.Unmarshal(mustRaw(raw["notes"]), &m.Notes); err != nil || strings.TrimSpace(m.Notes) == "" {
		return bad("notes")
	}

	// size 用 json.Number 收：JSON 沒有整數型別，直接吃 int64 會讓 1.5 這種
	// 值被悄悄接受或悄悄截掉，而它是「下載到多少就不再收」的上限。
	var artifacts map[string]struct {
		File   string      `json:"file"`
		Size   json.Number `json:"size"`
		SHA256 string      `json:"sha256"`
	}
	if err := json.Unmarshal(mustRaw(raw["artifacts"]), &artifacts); err != nil || len(artifacts) == 0 {
		return bad("artifacts")
	}
	m.Artifacts = make(map[string]Artifact, len(artifacts))
	for key, a := range artifacts {
		if !rePlatform.MatchString(key) {
			return bad("artifacts 的平台鍵 " + key)
		}
		if !reSafeFile.MatchString(a.File) {
			return bad("artifacts." + key + ".file")
		}
		size, err := a.Size.Int64()
		if err != nil || size <= 0 || strings.ContainsAny(a.Size.String(), ".eE") {
			return bad("artifacts." + key + ".size")
		}
		if !reSHA256.MatchString(a.SHA256) {
			return bad("artifacts." + key + ".sha256")
		}
		m.Artifacts[key] = Artifact{File: a.File, Size: size, SHA256: a.SHA256}
	}

	// 選用欄位：不合法就當作沒有（TS 也是這樣），不要整份退掉。
	var minVersion string
	if err := json.Unmarshal(mustRaw(raw["minVersion"]), &minVersion); err == nil && reVersion.MatchString(minVersion) {
		m.MinVersion = minVersion
	}
	var channel string
	if err := json.Unmarshal(mustRaw(raw["channel"]), &channel); err == nil && reChannelID.MatchString(channel) {
		m.Channel = channel
	}
	return &m, nil
}

// mustRaw 讓「欄位根本不存在」跟「欄位型別不對」走同一條路（都是 unmarshal 失敗）。
func mustRaw(r json.RawMessage) []byte {
	if len(r) == 0 {
		return []byte("null")
	}
	return r
}

// ArtifactKey 是這台機器要拿哪一個檔。
//
// 鍵是 TS（Node）那一套：作業系統用 win32→windows，架構用 node 的名字，
// 所以 Go 的 amd64 要翻成 x64 —— 兩邊看的是同一份 manifest，名字不能各說各話。
func ArtifactKey(goos, goarch string) string {
	arch := goarch
	switch goarch {
	case "amd64":
		arch = "x64"
	case "386":
		arch = "ia32"
	}
	return goos + "-" + arch
}

// VerifyBytes 檢查下載回來的位元組是不是 manifest 講的那一份。
//
// 這是簽章唯一能發揮作用的地方：簽章蓋住 sha256，所以只要這裡比對成立，
// 那串位元組就是簽章機器上那一份。少了這一步，簽章只是在保證「有人發過一個
// 叫 0.2.0 的版本」，跟你手上這個檔沒有關係。
func VerifyBytes(data []byte, a Artifact) error {
	if int64(len(data)) != a.Size {
		return gateErr(GateSize, "大小不符：拿到 %d bytes，manifest 說 %d", len(data), a.Size)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != a.SHA256 {
		return gateErr(GateSHA256, "sha256 不符：拿到 %s…，manifest 說 %s…", got[:16], a.SHA256[:16])
	}
	return nil
}

// CompareVersions 比大小，回傳 <0 / 0 / >0。
//
// 只認 x.y.z 加上選用的預發布後綴；有後綴的一律小於同號的正式版
// （0.2.0-beta.1 < 0.2.0），跟 semver 一致，也跟 TS 的 compareVersions 一致。
func CompareVersions(a, b string) int {
	an, ap := splitVersion(a)
	bn, bp := splitVersion(b)
	for i := 0; i < 3; i++ {
		if d := an[i] - bn[i]; d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	switch {
	case ap == bp:
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	case ap < bp:
		return -1
	default:
		return 1
	}
}

func splitVersion(v string) ([3]int, string) {
	core, pre, _ := strings.Cut(strings.TrimSpace(v), "-")
	var nums [3]int
	for i, part := range strings.SplitN(core, ".", 4) {
		if i > 2 {
			break
		}
		// 跟 JS 的 parseInt 一樣：只吃開頭的數字，讀不出來就是 0。
		end := 0
		for end < len(part) && part[end] >= '0' && part[end] <= '9' {
			end++
		}
		n, err := strconv.Atoi(part[:end])
		if err != nil {
			n = 0
		}
		nums[i] = n
	}
	return nums, pre
}

// IsNewerVersion：candidate 比 current 新嗎。
func IsNewerVersion(candidate, current string) bool { return CompareVersions(candidate, current) > 0 }
