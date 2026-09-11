//go:build windows

package menubar

import "golang.org/x/sys/windows"

// pidAlive 在 Windows 上不能用訊號問。
//
// `os.Process.Signal` 在這個平台只支援 Kill —— 送 0 會直接回
// "not supported by windows"，所以照抄 unix 那一版的結果是**每一台 Windows
// 都被畫成「沒有在執行」**，不管 daemon 跑得多好。
//
// 正確的問法是開一個只要求查詢的控制代號：拿得到就代表那個 pid 還在。
// 已經結束但還沒被回收的行程（zombie 的 Windows 版）也開得起來，所以再問一次
// 結束碼 —— STILL_ACTIVE 才算活著。
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		// 開得起來卻問不到結束碼：當它還在，寧可多畫一次「執行中」也不要
		// 對著一個活著的 daemon 說它不在。
		return true
	}
	const stillActive = 259 // STILL_ACTIVE
	return code == stillActive
}
