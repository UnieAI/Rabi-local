package config

import (
	"os"
	"path/filepath"
	"testing"
)

// 接管舊版的配對：使用者換一個實作，不該被要求重新配對一次。
//
// 舊版（TypeScript + bun）的家在 `~/.unieai/ava-local`，設定是 machine.json。
// 它跟這個程式的家是**不同的兩個目錄**，所以接管是「讀過來」不是「共用」。

func withLegacyHome(t *testing.T, write func(dir string)) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AVA_LOCAL_HOME", dir)
	write(dir)
}

func TestReadLegacyAdoptsAPairing(t *testing.T) {
	withLegacyHome(t, func(dir string) {
		os.WriteFile(filepath.Join(dir, "machine.json"), []byte(`{
			"appUrl":"https://agent.dev.unieai.com","machineId":"m-1","label":"roy 的 MacBook",
			"accessToken":"at","refreshToken":"rt","hmacKey":"k","grantedRoot":"/Users/roy/work","pairedAt":"2026-09-06"
		}`), 0o600)
	})
	l := ReadLegacy()
	if l == nil {
		t.Fatal("讀不到舊版的配對 —— 使用者會被要求重新配對一次")
	}
	c := &Config{}
	c.AdoptLegacy(l)
	if c.Server != "https://agent.dev.unieai.com" || c.MachineID != "m-1" {
		t.Fatalf("接管的是別台機器：%+v", c)
	}
	if c.DeviceToken != "rt" {
		t.Fatal("要接的是 refreshToken —— accessToken 是短命的，接過來馬上就過期")
	}
	if c.Label != "roy 的 MacBook" || len(c.Roots) != 1 || c.Roots[0] != "/Users/roy/work" {
		t.Fatalf("名字與授權資料夾沒跟過來：%+v", c)
	}
}

func TestReadLegacyRefusesHalfAConfig(t *testing.T) {
	// 少了任何一個，接管之後也連不上。那不叫接管，叫把使用者推進一個說不出
	// 原因的失敗 —— 而他手上那個配對碼早就用掉了。寧可讓他重新配對。
	for name, body := range map[string]string{
		"沒有 appUrl":       `{"machineId":"m","refreshToken":"r"}`,
		"沒有 machineId":    `{"appUrl":"https://a","refreshToken":"r"}`,
		"沒有 refreshToken": `{"appUrl":"https://a","machineId":"m"}`,
		"壞掉的 JSON":        `{`,
		"空的":              ``,
	} {
		t.Run(name, func(t *testing.T) {
			withLegacyHome(t, func(dir string) {
				os.WriteFile(filepath.Join(dir, "machine.json"), []byte(body), 0o600)
			})
			if l := ReadLegacy(); l != nil {
				t.Fatalf("不該接管：%+v", l)
			}
		})
	}
}

func TestReadLegacyWhenThereIsNoLegacy(t *testing.T) {
	withLegacyHome(t, func(string) {})
	if ReadLegacy() != nil {
		t.Fatal("沒有舊版卻說有")
	}
}

func TestAdoptNilIsANoop(t *testing.T) {
	c := &Config{Server: "https://kept"}
	c.AdoptLegacy(nil)
	if c.Server != "https://kept" {
		t.Fatal("nil 不該把既有的設定清掉")
	}
}

// ── 退休舊版 ────────────────────────────────────────────────────────────

func TestTakeoverDoesNotDeleteTheLegacyConfig(t *testing.T) {
	// 接管之後第一次連線如果失敗，那份 machine.json 是使用者唯一的退路。
	// 真的要清掉是 unpair 的事，不是換一個實作的事。
	var dir string
	withLegacyHome(t, func(d string) {
		dir = d
		os.WriteFile(filepath.Join(d, "machine.json"), []byte(`{"appUrl":"https://a","machineId":"m","refreshToken":"r"}`), 0o600)
	})
	Takeover()
	if _, err := os.Stat(filepath.Join(dir, "machine.json")); err != nil {
		t.Fatal("舊的設定被刪掉了 —— 接管失敗時使用者就沒有退路了")
	}
}

func TestTakeoverRetiresTheBinaryInsteadOfDeletingIt(t *testing.T) {
	var dir string
	withLegacyHome(t, func(d string) {
		dir = d
		os.MkdirAll(filepath.Join(d, "bin"), 0o700)
		os.WriteFile(LegacyBinary(), []byte("#!/bin/sh\n"), 0o755)
	})
	r := Takeover()
	if !r.BinaryRemoved {
		t.Fatal("舊的執行檔還在原位 —— 服務或指令列還叫得起它")
	}
	if _, err := os.Stat(LegacyBinary()); err == nil {
		t.Fatal("原位還在")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "ava-local.retired")); err != nil {
		if _, err2 := os.Stat(LegacyBinary() + ".retired"); err2 != nil {
			t.Fatal("改名之後找不到 —— 出事就救不回來了")
		}
	}
}

func TestTakeoverOnAMachineWithNoLegacyIsQuiet(t *testing.T) {
	t.Setenv("AVA_LOCAL_HOME", filepath.Join(t.TempDir(), "nope"))
	r := Takeover()
	if r.DidSomething() {
		t.Fatalf("沒有舊版卻說做了事：%+v", r)
	}
}
