//go:build windows

package runner

import (
	"os/exec"
	"strconv"
	"syscall"
)

// Windows 沒有可以直接送訊號的 process group 等價物，job object 又太重。
// taskkill /T 會連同子孫一起收掉，這是實務上最可靠的做法。
//
// CREATE_NEW_PROCESS_GROUP 仍然要設：沒有它，送給我們自己的 Ctrl+C
// 會一起傳給子行程，使用者關掉工具列圖示時會連帶殺掉正在跑的工作。
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

func killTree(pid int, _ syscall.Signal) error {
	return exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).Run()
}

// Windows 沒有 SIGTERM/SIGKILL 的區別 —— killTree 一律是強制的。
// 型別留著是為了讓 exec.go 不用分平台寫。
func termSignal() syscall.Signal { return syscall.Signal(0) }
func killSignal() syscall.Signal { return syscall.Signal(0) }
