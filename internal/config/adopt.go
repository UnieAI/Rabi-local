package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// LegacyHome 是 TypeScript 版 Rabi Local（bun 單一執行檔）的家。
//
// **兩個實作共用同一台電腦的時候，這個路徑是接管的入口。** 它裡面有那台機器
// 的憑證與授權資料夾 —— 讀得到它，使用者就不必為了換一個實作重新配對一次。
func LegacyHome() string {
	if v := os.Getenv("AVA_LOCAL_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".unieai", "ava-local")
}

// LegacyBinary 是它的執行檔。Windows 上多一個副檔名。
func LegacyBinary() string {
	name := "ava-local"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	h := LegacyHome()
	if h == "" {
		return ""
	}
	return filepath.Join(h, "bin", name)
}

// LegacyConfig 是 machine.json 裡我們**接管得了**的那幾欄。
//
// sandbox 的那幾個選項刻意不抄：它們屬於舊實作自己的機制，由新實作重新決定。
//
// **`hmacKey` 一定要抄。** 我第一版沒抄，理由是「那是 app 跟舊實作共用的東西」
// —— 結果是 Go 版對一台**還沒註冊 passkey 的機器什麼都不讓做**：app 的 HMAC
// 票驗不了，而使用者要註冊第一把 passkey 又得先有一台動得了的機器。那不是
// 「比較安全」，是把人鎖在門外，而停擺正是攻擊者要的東西。
//
// 開關仍然在信任清單：這台機器只要註冊過任何一把金鑰，HMAC 票就一律拒絕。
type LegacyConfig struct {
	AppURL       string `json:"appUrl"`
	MachineID    string `json:"machineId"`
	Label        string `json:"label"`
	RefreshToken string `json:"refreshToken"`
	GrantedRoot  string `json:"grantedRoot"`
	HmacKey      string `json:"hmacKey"`
}

// ReadLegacy 讀舊版的設定。回 nil 表示「沒有舊版」或「讀不出可用的東西」——
// 兩者對呼叫端是同一件事：沒有東西可以接管，照正常流程配對。
func ReadLegacy() *LegacyConfig {
	h := LegacyHome()
	if h == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(h, "machine.json"))
	if err != nil {
		return nil
	}
	var c LegacyConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil
	}
	// 少了任何一個，接管之後也連不上 —— 那就不叫接管，叫把使用者推進一個
	// 說不出原因的失敗。寧可讓他重新配對一次。
	if c.AppURL == "" || c.MachineID == "" || c.RefreshToken == "" {
		return nil
	}
	return &c
}

// AdoptLegacy 把舊版的配對搬過來。
//
// **不刪舊的東西** —— 退休那一步是 `takeover` 的事，而且必須在「新的這一份
// 真的寫下去」之後才做。反過來的話，中途失敗會留下一台既沒有舊設定、也沒有
// 新設定的電腦，而使用者手上那個配對碼早就用掉了。
func (c *Config) AdoptLegacy(l *LegacyConfig) {
	if l == nil {
		return
	}
	c.mu.Lock()
	c.Server = l.AppURL
	c.MachineID = l.MachineID
	c.DeviceToken = l.RefreshToken
	c.HmacKey = l.HmacKey
	if l.Label != "" {
		c.Label = l.Label
	}
	if l.GrantedRoot != "" {
		c.Roots = []string{l.GrantedRoot}
	}
	c.mu.Unlock()
}
