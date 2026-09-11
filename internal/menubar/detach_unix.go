//go:build !windows

package menubar

import (
	"os/exec"
	"syscall"
)

// detach 讓 daemon 進自己的 session group：選單列的小工具被關掉、或使用者
// 登出那個終端機時，不要把連線一起帶走。
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
