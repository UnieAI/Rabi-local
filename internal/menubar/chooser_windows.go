package menubar

import (
	"os/exec"
	"strings"
)

// Windows 的「瀏覽資料夾」視窗。走 PowerShell 是因為它一定在，而且不必為了
// 一個對話框把整個 Win32 shell API 綁進來。
//
// 使用者按取消時 ShowDialog 回 Cancel，那時候印不出任何東西 —— 空字串就是
// 「他不想換」，呼叫端什麼都不做。
func chooseFolder(start string) string {
	ps := `Add-Type -AssemblyName System.Windows.Forms
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.Description = 'Which folder may the agent work in?'
$d.SelectedPath = '` + strings.ReplaceAll(start, "'", "''") + `'
if ($d.ShowDialog() -eq 'OK') { [Console]::Out.Write($d.SelectedPath) }`
	out, err := exec.Command("powershell", "-NoProfile", "-STA", "-Command", ps).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
