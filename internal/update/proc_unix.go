//go:build !windows

package update

import "syscall"

// detachAttrs 讓新開的行程**脫離這個行程**。
//
// 不 Setsid 的話，新的 daemon 會留在同一個 process group 裡：使用者關掉終端機、
// 或者 systemd 收掉這個 unit 的時候，剛換好的那一個會跟著一起被殺 —— 更新看起來
// 成功，電腦卻在幾秒後離線。
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
