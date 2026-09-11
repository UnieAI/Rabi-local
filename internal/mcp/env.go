// env.go —— 第三方 MCP server 的子行程拿得到什麼環境變數。
//
// 起 server 的是**我們**，所以它預設會繼承這個程式的整份環境 —— 而這個程式
// 的環境裡有連線憑證、有伺服器位址。使用者授權一台 MCP server 的意思是
// 「可以叫它做事」，不是「把我登入雲端的東西交給它」。
//
// 所以這裡是**允許清單**，不是封鎖清單：想不到的變數一律不給。封鎖清單的
// 問題是每加一個新的祕密就要記得回來改，而忘記的那一次沒有任何症狀。
package mcp

import (
	"regexp"
	"sort"
	"strings"
)

// passThrough 是「不給就跑不起來」的那些：找得到程式（PATH）、找得到家目錄、
// 語系與暫存資料夾。
var passThrough = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"LANG": true, "LANGUAGE": true, "TERM": true, "TMPDIR": true, "TMP": true, "TEMP": true,
	"XDG_RUNTIME_DIR": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true, "XDG_CACHE_HOME": true,
	"SYSTEMROOT": true, "SystemRoot": true, "COMSPEC": true, "ComSpec": true,
	"USERPROFILE": true, "APPDATA": true, "LOCALAPPDATA": true, "PATHEXT": true, "WINDIR": true,
	"TZ": true, "COLORTERM": true, "EDITOR": true, "PWD": true,
}

var passPrefix = []string{"LC_"}

// secretLike 是**連使用者在授權檔裡明寫也不給**的形狀。理由：授權檔裡寫
// `"env": {"OPENAI_API_KEY": "..."}` 的人多半以為那是給 server 用的，但那把
// 金鑰接下來會跟著 server 的每一次外連走出這台電腦。想這麼做的人請自己用
// 別的名字，那至少是個明確的決定。
//
// _BASE_URL 與 _PROXY 在列表上是因為改寫它們等於把流量導到別人的伺服器
// （CVE-2026-21852 的形狀）。
var secretLike = regexp.MustCompile(`(?i)(_API_KEY|_APIKEY|_TOKEN|_SECRET|_PASSWORD|_BASE_URL|_PROXY|^AVA_LOCAL_|^COPILOT_DESKTOP_)`)

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ChildEnv 回傳一個第三方子行程該拿到的環境（"K=V" 形式，可以直接指派給
// exec.Cmd.Env）。
//
// source 通常是 os.Environ()；extra 是授權檔裡那台 server 自己的 env。
// 輸出是排序過的 —— 同樣的輸入永遠得到同樣的一份，測試才咬得住。
func ChildEnv(source []string, extra map[string]string) []string {
	kept := map[string]string{}
	for _, kv := range source {
		k, v, found := strings.Cut(kv, "=")
		if !found || k == "" {
			continue
		}
		if secretLike.MatchString(k) {
			continue
		}
		if passThrough[k] || hasAnyPrefix(k, passPrefix) {
			kept[k] = v
		}
	}
	for k, v := range extra {
		if envNameRe.MatchString(k) && !secretLike.MatchString(k) {
			kept[k] = v
		}
	}
	out := make([]string, 0, len(kept))
	for k, v := range kept {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
