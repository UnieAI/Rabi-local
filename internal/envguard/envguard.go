// Package envguard 決定 daemon 讓什麼東西流進子行程，以及什麼情況下它乾脆
// 拒絕啟動。
//
// 移植自 runtime/apps/ava-local/src/env-guard.ts，行為逐條等價。
//
// ## 威脅
//
//	· **供應商的 API 金鑰不該存在於這台裝置上**，更不該被交給代理人跑的指令。
//	· 一個被改寫過的 `*_BASE_URL` 或 proxy 變數，不可以無聲地把 daemon
//	  （或它跑的工具）導到別人的伺服器（CVE-2026-21852 那個形狀）。
//
// 所以子行程的環境是**白名單**，而不是「把危險的挑掉」。黑名單的問題是它
// 對「明天新增的那一個變數」永遠是錯的 —— 而那一個正是攻擊者會用的。
//
// ## 這個套件曾經只存在於 MCP 那條路上
//
// 移植的時候白名單先落在 `internal/mcp/env.go`，於是 **exec 的子行程拿到的
// 是整份 os.Environ()** —— 代理人跑的指令看得到 daemon 自己的憑證。規則寫好了
// 但只接了一條路，是這個專案最常出事的形狀。抽成獨立套件就是為了讓「還有誰
// 沒接」變成一個看得見的問題。
package envguard

import (
	"os"
	"regexp"
	"strings"
)

// passThrough 是已知安全的那幾個。**這是白名單的全部** —— 不在這裡就不給。
var passThrough = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"LANG": true, "LANGUAGE": true, "TERM": true, "TMPDIR": true, "TMP": true, "TEMP": true,
	"XDG_RUNTIME_DIR": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true, "XDG_CACHE_HOME": true,
	"SYSTEMROOT": true, "SystemRoot": true, "COMSPEC": true, "ComSpec": true,
	"USERPROFILE": true, "APPDATA": true, "LOCALAPPDATA": true, "PATHEXT": true, "WINDIR": true,
	"TZ": true, "COLORTERM": true, "EDITOR": true, "PWD": true,
}

var passPrefix = []string{"LC_"}

// secretLike 認得出「這個名字聞起來像祕密或像重導」的形狀。
//
// 它同時作用在白名單**之上**：就算某個名字碰巧在 passThrough 裡，只要它長得
// 像祕密就不給。兩道都要過。
var secretLike = regexp.MustCompile(`(?i)(_API_KEY|_APIKEY|_TOKEN|_SECRET|_PASSWORD|_BASE_URL|_PROXY|^AVA_LOCAL_)`)

var proxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}

var validName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ChildEnv 是一個工具子行程拿得到的環境：只有已知安全的那幾個。
//
// `source` 是 `os.Environ()` 那種 `K=V` 切片；`extra` 是這一次呼叫要額外加的
// （例如終端機的 TERM）。**extra 一樣要過 secretLike** —— 呼叫端把祕密塞進
// extra 繞過白名單，是這道門最可能被破的方式。
func ChildEnv(source []string, extra map[string]string) []string {
	out := make([]string, 0, 24)
	for _, kv := range source {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		k := kv[:i]
		if secretLike.MatchString(k) {
			continue
		}
		if passThrough[k] || hasAnyPrefix(k, passPrefix) {
			out = append(out, kv)
		}
	}
	for k, v := range extra {
		if validName.MatchString(k) && !secretLike.MatchString(k) {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// ChildEnvFromOS 是 ChildEnv(os.Environ(), extra) 的捷徑。
func ChildEnvFromOS(extra map[string]string) []string { return ChildEnv(os.Environ(), extra) }

// Verdict 是啟動檢查的結果。
type Verdict struct {
	OK       bool
	Problems []string
}

// GuardStartup：環境有可能把流量重導或攔截的時候，**不要跑**。
//
// `pinnedAppURL` 是配對當下存下來的那一個。用環境變數覆蓋成別的網址不是
// 便利功能，那正是攻擊本身。
//
// 注意 `ok` 的算法：「這台機器上有供應商金鑰」是**警告不是致命**（我們不傳給
// 工具，那句話本身就是處置），其餘是致命。兩者混在一起的話，一個有裝
// OPENAI_API_KEY 的開發者會發現 daemon 根本啟動不了。
func GuardStartup(pinnedAppURL string, source []string) Verdict {
	env := map[string]string{}
	for _, kv := range source {
		if i := strings.IndexByte(kv, '='); i > 0 {
			env[kv[:i]] = kv[i+1:]
		}
	}
	var problems []string
	fatal := 0
	add := func(s string, isFatal bool) {
		problems = append(problems, s)
		if isFatal {
			fatal++
		}
	}

	if env["NODE_TLS_REJECT_UNAUTHORIZED"] == "0" {
		add("NODE_TLS_REJECT_UNAUTHORIZED=0 關掉了 TLS 驗證", true)
	}
	for _, v := range proxyVars {
		if env[v] != "" && env["AVA_LOCAL_ALLOW_PROXY"] != "1" {
			add(v+" 被設了（如果那個 proxy 是你自己的，設 AVA_LOCAL_ALLOW_PROXY=1）", true)
		}
	}
	if override := strings.TrimSpace(env["AVA_LOCAL_APP_URL"]); override != "" && pinnedAppURL != "" {
		if trimSlash(override) != trimSlash(pinnedAppURL) {
			add("AVA_LOCAL_APP_URL（"+override+"）跟配對的那一個（"+pinnedAppURL+"）不一樣；請重新配對，不要用覆蓋的", true)
		}
	}
	for k := range env {
		if providerKey.MatchString(k) {
			// 警告，不致命：我們不會把它傳給工具，而那句話本身就是處置。
			add(k+" 出現在這台機器上 —— 供應商金鑰不該存在於裝置裡；daemon 不會把它傳給任何工具", false)
		}
	}
	return Verdict{OK: fatal == 0, Problems: problems}
}

var providerKey = regexp.MustCompile(`(?i)^(OPENAI|ANTHROPIC|UNIEAI|DEEPSEEK|GEMINI|AZURE)\w*(_API_KEY|_APIKEY)$`)

func trimSlash(s string) string { return strings.TrimRight(s, "/") }

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
