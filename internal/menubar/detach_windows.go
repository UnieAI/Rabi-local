//go:build windows

package menubar

import "os/exec"

// Windows 沒有 setsid；這個小工具目前也只在 macOS 上出現，這裡只是讓
// `go build ./...` 在所有平台上都過得去。
func detach(cmd *exec.Cmd) {}
