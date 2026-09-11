package menubar

import (
	"os"
	"os/exec"
	"path/filepath"
)

// systemd --user。單元名跟 TS 那一支的 service.ts 一樣，不要改。
const systemdUnit = "ava-local.service"

func unitPath() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".config", "systemd", "user", systemdUnit)
}

func serviceInstalled() bool {
	p := unitPath()
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func serviceStop() error  { return exec.Command("systemctl", "--user", "stop", systemdUnit).Run() }
func serviceStart() error { return exec.Command("systemctl", "--user", "start", systemdUnit).Run() }
