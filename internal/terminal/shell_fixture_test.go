package terminal

import "runtime"

// testShell 是這些測試假裝存在的那一支 shell。
//
// **為什麼不能寫死 /bin/sh**：`shellCandidates` 是平台專屬的，而 Windows 那一版
// 刻意忽略 $SHELL（會設它的通常是 git-bash，寫進去的 /usr/bin/bash 在 Windows
// 打不開）。所以在 Windows 上注入一個只認得 /bin/sh 的 LookPath，等於告訴
// resolveShell「一支 shell 都沒有」，整包終端機測試會以 no_shell 全紅 ——
// 而那紅的不是產品，是這個替身。2026-09-11 第一次在 Windows 跑 CI 時撞到。
func testShell() string {
	if runtime.GOOS == "windows" {
		// 候選清單裡的最後一個：ComSpec 沒設時的預設值。
		return `C:\Windows\System32\cmd.exe`
	}
	return "/bin/sh"
}

// testLookPath 只認得 testShell()，這樣「選到哪一支」仍然是被測出來的，
// 而不是「什麼都說有」。
func testLookPath(p string) bool { return p == testShell() }

// outsideDir 是一個絕對而且一定在授權資料夾外面的目錄。
//
// 同一個理由：filepath.IsAbs("/etc") 在 Windows 是 false，所以那個字串會被當成
// 相對路徑接到授權資料夾後面 —— 合法、通過、而測試紅在一個其實沒有破洞的地方。
func outsideDir() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32`
	}
	return "/etc"
}
