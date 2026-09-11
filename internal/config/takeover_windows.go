//go:build windows

package config

import (
	"os/exec"
	"strconv"
)

// Windows 上舊版沒有服務（TS 版的 serviceKind 在 win32 回 none），所以這裡
// 只要能停掉行程就夠了。
func stopLegacyService(r *TakeoverResult) bool { return false }

// stopPid：先好好請它走，不走再 /F。`/T` 連子行程一起，不然換版之後會留下
// 一串沒有人殺得掉的孤兒。
func stopPid(pid int) bool {
	p := strconv.Itoa(pid)
	if exec.Command("taskkill", "/PID", p).Run() == nil {
		return true
	}
	return exec.Command("taskkill", "/F", "/T", "/PID", p).Run() == nil
}
