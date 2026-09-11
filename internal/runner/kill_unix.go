//go:build !windows

package runner

import (
	"os/exec"
	"syscall"
)

// setProcessGroup 讓子行程自成一個 process group。
//
// 不做這件事的話，`bash -lc "npm install"` 被中止時只有 bash 會死，
// 它啟動的 npm 和 node 會變成孤兒繼續跑 —— 使用者關掉桌面程式之後，
// 他的電腦上還有東西在動，而且沒有人能再殺掉它。
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killTree 對整個 process group 送訊號。負的 pid 就是「這個 group 的所有人」。
func killTree(pid int, sig syscall.Signal) error {
	if err := syscall.Kill(-pid, sig); err != nil {
		// group 不存在（例如 Setpgid 失敗）時退回單一行程，有殺到總比沒有好。
		return syscall.Kill(pid, sig)
	}
	return nil
}

func termSignal() syscall.Signal { return syscall.SIGTERM }
func killSignal() syscall.Signal { return syscall.SIGKILL }
