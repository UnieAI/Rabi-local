//go:build !windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// stopLegacyService 關掉舊版的開機自動啟動。
//
// **不透過舊版的執行檔去問。** 磁碟上那一個可能連 `uninstall-service` 這個
// 子指令都還沒有（它是後來才加的），而我們正要把它移開。直接看單元檔／plist
// 在不在，這樣對每一個版本的舊版都成立。
func stopLegacyService(r *TakeoverResult) bool {
	done := false

	// systemd --user
	if _, err := exec.LookPath("systemctl"); err == nil {
		if exec.Command("systemctl", "--user", "cat", "ava-local.service").Run() == nil {
			_ = exec.Command("systemctl", "--user", "disable", "--now", "ava-local.service").Run()
			done = true
			r.Notes = append(r.Notes, "關掉了 systemd 的開機自動啟動（ava-local.service）")
		}
	}

	// launchd
	if home, err := os.UserHomeDir(); err == nil {
		plist := filepath.Join(home, "Library", "LaunchAgents", "com.unieai.ava-local.plist")
		if _, err := os.Stat(plist); err == nil {
			uid := os.Getuid()
			if exec.Command("launchctl", "bootout", "gui/"+itoa(uid)+"/com.unieai.ava-local").Run() != nil {
				_ = exec.Command("launchctl", "unload", plist).Run()
			}
			done = true
			r.Notes = append(r.Notes, "關掉了 launchd 的開機自動啟動（com.unieai.ava-local）")
		}
	}
	return done
}

// stopPid 先請它自己收尾，不走才動手。
//
// SIGTERM 是有意義的：舊版收到它會把還在跑的子行程一起收掉。直接 SIGKILL
// 會留下一堆沒有人殺得掉的孤兒（它自己的註解記著這件事）。
func stopPid(pid int) bool {
	if syscall.Kill(pid, syscall.SIGTERM) != nil {
		return false
	}
	for i := 0; i < 50; i++ {
		if syscall.Kill(pid, 0) != nil {
			return true // 走了
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	for i := 0; i < 20; i++ {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
