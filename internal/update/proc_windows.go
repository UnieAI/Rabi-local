//go:build windows

package update

import "syscall"

// DETACHED_PROCESS：新的行程不要繼承這個行程的主控台。syscall 沒有這個常數，
// 所以寫成字面值（值來自 Win32 的 CreateProcess 旗標）。
const detachedProcess = 0x00000008

// detachAttrs 讓新開的行程脫離這個行程 —— 使用者關掉視窗的時候，剛換好的那一個
// 不該跟著被收掉。
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP}
}
