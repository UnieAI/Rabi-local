package terminal

import (
	"os"
	"regexp"
	"strconv"
	"strings"
)

// clampSize 把版面報上來的尺寸夾進 PTY 收得下的範圍。
//
// 見 Service.Resize 的說明：呼叫端是一個版面，不是一個人。0、負數、大得離譜的
// 值都不是錯誤，是渲染過程中的一瞬間。
func clampSize(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	if value > 1000 {
		return 1000
	}
	return value
}

// resolveShell 決定這個終端機要跑哪一個程式。
//
// **相對路徑的 $SHELL 一律忽略，不會去 PATH 找。** 那個搜尋會用 daemon 自己的
// PATH，而不是使用者登入 shell 被找到的那條；找到一個同名的別的執行檔，比用
// 寫在文件裡的退路更糟。
func resolveShell(env map[string]string, exists func(string) bool) (string, error) {
	for _, candidate := range shellCandidates(env) {
		if candidate != "" && exists(candidate) {
			return candidate, nil
		}
	}
	return "", errf(CodeNoShell, "%s 都不可用，開不了終端機。", strings.Join(shellCandidates(env), "、"))
}

// terminalTitle 是分頁上的字：user@host，就像終端機模擬器替視窗取名那樣。
func terminalTitle(env map[string]string, hostname string) string {
	user := firstNonEmpty(env["USER"], env["LOGNAME"], env["USERNAME"])
	if user == "" {
		// 容器或被剝乾淨的環境可能兩個都沒有。"shell" 是一個誠實的替代品，
		// 比對著使用者印一個 undefined@ 好。
		user = "shell"
	}
	host := hostname
	if i := strings.Index(host, "."); i >= 0 {
		// 一個窄窄的分頁上，後面那串網域是雜訊。
		host = host[:i]
	}
	if host == "" {
		return user
	}
	return user + "@" + host
}

// PASS_THROUGH / SECRET_LIKE 是從 runtime/apps/ava-local/src/env-guard.ts 搬過來的。
//
// 終端機不可以變成那個唯一漏東西的工具：每一個別的工具都被這道白名單擋著，
// 而這裡跑的是一個人自己的 shell。等 Go 版有了自己的 env-guard 套件，這一段
// 就搬過去，這裡只留呼叫。
var passThrough = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"LANG": true, "LANGUAGE": true, "TERM": true, "TMPDIR": true, "TMP": true, "TEMP": true,
	"XDG_RUNTIME_DIR": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true, "XDG_CACHE_HOME": true,
	"SYSTEMROOT": true, "SystemRoot": true, "COMSPEC": true, "ComSpec": true,
	"USERPROFILE": true, "APPDATA": true, "LOCALAPPDATA": true, "PATHEXT": true, "WINDIR": true,
	"TZ": true, "COLORTERM": true, "EDITOR": true, "PWD": true,
	// Windows 上少了這三個，很多程式（含 PowerShell 自己）會找不到暫存區與
	// 使用者名稱。它們不是秘密。
	"USERNAME": true, "USERDOMAIN": true, "PROGRAMDATA": true,
}

var secretLike = regexp.MustCompile(`(?i)(_API_KEY|_APIKEY|_TOKEN|_SECRET|_PASSWORD|_BASE_URL|_PROXY|^AVA_LOCAL_)`)

// childEnv 是一個子行程拿得到的環境：只有已知安全的那些。
func childEnv(source map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range source {
		if secretLike.MatchString(k) {
			continue
		}
		if passThrough[k] || strings.HasPrefix(k, "LC_") {
			out[k] = v
		}
	}
	return out
}

// terminalEnv 是這個終端機的 shell 會看到的環境。
//
// **雲端送下來的 extra 也要過同一道白名單。** 這一點跟 TS 版一樣，而且是刻意的：
// 「可以在別人的 shell 裡種任意環境變數」等於可以改 PATH，等於下一個 npm 不是
// 他的 npm。extra 出現在核准票的 subject 裡，正是為了讓卡片說得出這件事。
//
// TERM 與 COLORTERM 最後才蓋上去：shell 和它跑的每一個全螢幕程式都靠它們決定
// 自己可以送哪些跳脫序列。
func terminalEnv(source []string, extra map[string]string, cwd string) map[string]string {
	merged := envMap(source)
	for k, v := range extra {
		merged[k] = v
	}
	merged["PWD"] = cwd
	out := childEnv(merged)
	out["TERM"] = "xterm-256color"
	out["COLORTERM"] = "truecolor"
	return out
}

// envMap 把 os.Environ() 那種 KEY=VALUE 陣列變成 map。
func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, e := range env {
		if i := strings.Index(e, "="); i > 0 {
			out[e[:i]] = e[i+1:]
		}
	}
	return out
}

// executableExists 是預設的「這個 shell 在不在」。
func executableExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return isExecutable(info)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func itoa(n int) string { return strconv.Itoa(n) }
