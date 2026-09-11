package menubar

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// 這幾個跟 TS 那一支的 service.ts 用同一個 label 與同一組指令。**不要改這個
// 字串** —— 改了就等於把使用者已經裝好的那個服務變成孤兒。
const launchdLabel = "com.unieai.ava-local"

func plistPath() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, "Library", "LaunchAgents", launchdLabel+".plist")
}

func serviceInstalled() bool {
	p := plistPath()
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func guiTarget() string { return "gui/" + strconv.Itoa(os.Getuid()) }

func serviceStop() error {
	return exec.Command("launchctl", "bootout", guiTarget()+"/"+launchdLabel).Run()
}

func serviceStart() error {
	return exec.Command("launchctl", "bootstrap", guiTarget(), plistPath()).Run()
}
