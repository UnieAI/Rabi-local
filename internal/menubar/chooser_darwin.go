package menubar

import (
	"os/exec"
	"strings"
)

// chooseFolder 用系統自己的選取視窗。
//
// 刻意不自己畫一個檔案瀏覽器：使用者要授權的是他自己電腦上的一個資料夾，而
// 「挑一個資料夾」在每個作業系統上早就有一個所有人都認得的視窗。取消會讓那支
// 程式以非 0 結束，那時候回空字串。
func chooseFolder(start string) string {
	script := `POSIX path of (choose folder with prompt "Which folder may the agent work in?")`
	if start != "" {
		script = `POSIX path of (choose folder with prompt "Which folder may the agent work in?" default location POSIX file ` + quoteAppleScript(start) + `)`
	}
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return ""
	}
	// osascript 給的路徑結尾會多一個 /，而 grantedRoot 一律不帶。
	return strings.TrimSuffix(strings.TrimSpace(string(out)), "/")
}

func quoteAppleScript(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
