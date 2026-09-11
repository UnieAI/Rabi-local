//go:build windows

package terminal

import "os"

// shellCandidates 是 Windows 上要依序試的程式。
//
// **$SHELL 在這裡是刻意忽略的**：會設它的通常是 git-bash，而它寫進去的是
// /usr/bin/bash —— 一個 Windows 打不開的路徑。照著它走只會得到一個開不起來的
// 終端機，而且錯誤訊息會指向一個看起來像 bug 的地方。
//
// 順序是使用者最可能認得的那一個優先：PowerShell 7、內建的 PowerShell 5，
// 最後才是 cmd.exe。
func shellCandidates(env map[string]string) []string {
	root := firstNonEmpty(env["SystemRoot"], env["SYSTEMROOT"], `C:\Windows`)
	programFiles := firstNonEmpty(env["ProgramFiles"], env["PROGRAMFILES"], `C:\Program Files`)
	return []string{
		programFiles + `\PowerShell\7\pwsh.exe`,
		root + `\System32\WindowsPowerShell\v1.0\powershell.exe`,
		firstNonEmpty(env["ComSpec"], env["COMSPEC"], root+`\System32\cmd.exe`),
	}
}

// isExecutable：Windows 上沒有執行位元，檔案存在就算數。呼叫端給的是我們自己
// 列出來的那三個路徑，不是使用者送下來的字串。
func isExecutable(info os.FileInfo) bool { return !info.IsDir() }
