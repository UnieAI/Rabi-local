// Package config 是這個程式在使用者電腦上唯一的持久狀態。
//
// 一個 JSON 檔，放在 ~/.unieai/copilot-desktop/config.json（Windows 是
// %AppData%\unieai\copilot-desktop\config.json）。刻意不用系統鑰匙圈：
// 那需要 cgo，而 cgo 會讓三平台交叉編譯變成一件麻煩事，換來的安全性提升
// 在這個威脅模型下有限（能讀到這個檔的人已經在使用者的帳號裡了）。
// 檔案權限是 0600。
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"crypto/rand"
	"encoding/hex"
)

// Config 是整個程式的設定。
type Config struct {
	// Server 是這台電腦要接哪一個 copilot-v2。
	//
	// **公司地端和公有雲是不同的網址**，而且同一個人可能兩邊都有帳號。
	// 這個值決定了：連哪裡、去哪裡登入、OTA 從哪裡拿。
	//
	// 使用者不會手動輸入它（見 README 的「下載即設定」）——
	// 它由配對連結帶進來，或由 --server 覆寫。
	Server string `json:"server"`

	// MachineID 是這台電腦在那個伺服器上的身分。**跟著 Server 走** ——
	// 換伺服器就是換一台機器，不能沿用（那邊的資料庫裡沒有這個 id）。
	MachineID string `json:"machineId"`

	// DeviceToken 是登入之後拿到的長期憑證，用來換短命的連線憑證。
	DeviceToken string `json:"deviceToken"`

	// HmacKey 是配對時跟 app 建立的那把共用金鑰，用來驗 app 簽的核准票。
	//
	// **它證明的是「這個核准經過 app 之後沒有被改」，不是「app 是誠實的」**
	// —— 金鑰是共用的，能在 app 行程裡跑程式的人簽得出任何一張票。真正的
	// 那一道是使用者的裝置簽的（internal/devicekeys）。
	//
	// 留著它的理由：已經配對好的機器上裝置公鑰的數量都是零，只收裝置票等於
	// 讓所有人的機器停擺，而他們要註冊第一把 passkey 得先有一台動得了的機器。
	HmacKey string `json:"hmacKey"`

	// Roots 是使用者批准過的資料夾。**這份清單是本機說了算** ——
	// 伺服器可以要求新增，但要經過使用者同意才會寫進來。
	Roots []string `json:"roots"`

	// Label 顯示在網頁的機器清單上。預設是主機名稱。
	Label string `json:"label"`

	path string
	mu   sync.Mutex
}

// Dir 回傳設定檔所在的資料夾。
func Dir() string {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("AppData"); base != "" {
			return filepath.Join(base, "unieai", "copilot-desktop")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".unieai"
	}
	return filepath.Join(home, ".unieai", "copilot-desktop")
}

// Load 讀設定；檔案不存在就回一份空的（不是錯誤 —— 第一次執行本來就沒有）。
func Load() (*Config, error) {
	p := filepath.Join(Dir(), "config.json")
	c := &Config{path: p}
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	c.path = p
	return c, nil
}

// Save 原子地寫回設定 —— 同目錄暫存檔再 rename。直接覆寫的話，
// 寫到一半被中斷會留下一個壞掉的 JSON，下次啟動就登入狀態全失。
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// EnsureMachineID 第一次執行時產生一個機器 id。
func (c *Config) EnsureMachineID() string {
	if c.MachineID != "" {
		return c.MachineID
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	c.MachineID = "dm-" + hex.EncodeToString(b)
	return c.MachineID
}

// EnsureLabel 預設用主機名稱 —— 使用者在網頁上要認得出哪一台是哪一台。
func (c *Config) EnsureLabel() string {
	if c.Label != "" {
		return c.Label
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		c.Label = h
	} else {
		c.Label = "我的電腦"
	}
	return c.Label
}

// SetServer 換伺服器。**會一併清掉機器身分與登入狀態** ——
// machineId 和 token 都是那個伺服器發的，帶到另一個伺服器只會得到
// 一個看不懂的錯誤。授權過的資料夾保留，那是使用者對自己電腦的決定，
// 跟連哪個伺服器無關。
func (c *Config) SetServer(url string) {
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if url == c.Server {
		return
	}
	c.Server = url
	c.MachineID = ""
	c.DeviceToken = ""
}

// AddRoot 把一個資料夾加進授權清單（已經涵蓋在內就不重複加）。
func (c *Config) AddRoot(root string) bool {
	root = filepath.Clean(root)
	for _, r := range c.Roots {
		if r == root {
			return false
		}
	}
	c.Roots = append(c.Roots, root)
	return true
}

// RemoveRoot 收回一個資料夾的授權。
func (c *Config) RemoveRoot(root string) bool {
	root = filepath.Clean(root)
	out := c.Roots[:0]
	found := false
	for _, r := range c.Roots {
		if r == root {
			found = true
			continue
		}
		out = append(out, r)
	}
	c.Roots = out
	return found
}
