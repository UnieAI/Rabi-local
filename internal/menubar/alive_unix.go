//go:build !windows

package menubar

import (
	"os"
	"syscall"
)

// pidAlive 只問「這個 pid 現在有沒有人」。
//
// 刻意不去核對它是不是 Rabi Local：那需要讀 /proc 或叫 ps，而這個小工具每幾秒
// 就會問一次。核對留給 `ava-local doctor`，它一次就好。
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
