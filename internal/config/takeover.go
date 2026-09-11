package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Takeover 把舊版（TypeScript + bun 的 Rabi Local）從這台電腦上退下來。
//
// ## 順序不能反，而且殺行程是不夠的
//
// 舊版如果裝過開機自動啟動，systemd 的單元寫著 `Restart=always`、launchd 的
// plist 寫著 `KeepAlive` —— **它會在五秒內自己回來**。先關服務再殺行程，
// 反過來的話它會在中間復活，然後兩個實作搶同一張憑證、同一條 relay 連線，
// 而使用者看到的是「連上了又斷、斷了又連」。
//
// ## 為什麼不刪設定檔
//
// `machine.json` 裡有那台機器的憑證與稽核鏈。新版已經用 `AdoptLegacy` 把
// 配對接過來了，但**舊的那一份留著**：接管之後第一次連線如果失敗，那是使用者
// 唯一的退路。真的要清掉是 `unpair` 的事，不是換一個實作的事。
//
// 回傳做了哪幾件事，給畫面照實說 —— 「已接管」如果是猜的，那它就是在說謊。
type TakeoverResult struct {
	ServiceStopped bool
	ProcessStopped []int
	BinaryRemoved  bool
	Notes          []string
}

func (r TakeoverResult) DidSomething() bool {
	return r.ServiceStopped || len(r.ProcessStopped) > 0 || r.BinaryRemoved
}

// Takeover 停掉舊版並把它的執行檔移開。設定檔**不動**。
func Takeover() TakeoverResult {
	var r TakeoverResult
	home := LegacyHome()
	if home == "" {
		return r
	}
	if _, err := os.Stat(home); err != nil {
		return r // 沒有舊版
	}

	// 1. 開機自動啟動先關掉。不關的話下面殺完它就回來了。
	if stopLegacyService(&r) {
		r.ServiceStopped = true
	}

	// 2. 停掉正在跑的。pid 檔與「找得到的同名行程」都看 —— pid 檔被後來的
	//    daemon 覆寫過的話，會留下一個沒有 pid 指得到的孤兒。
	for _, pid := range legacyPids(home) {
		if stopPid(pid) {
			r.ProcessStopped = append(r.ProcessStopped, pid)
		}
	}

	// 3. 把執行檔移開（改名不刪除：出事的時候還救得回來，而且 100MB 的檔案
	//    刪掉就沒了）。改名之後它再也不會被服務或指令列叫起來。
	if bin := LegacyBinary(); bin != "" {
		if _, err := os.Stat(bin); err == nil {
			retired := bin + ".retired"
			_ = os.Remove(retired)
			if err := os.Rename(bin, retired); err == nil {
				r.BinaryRemoved = true
			} else {
				r.Notes = append(r.Notes, fmt.Sprintf("舊的執行檔移不開（%v）—— 它不會再被叫起來，但還佔著空間", err))
			}
		}
	}
	return r
}

// legacyPids 找出舊版正在跑的行程。
func legacyPids(home string) []int {
	seen := map[int]bool{}
	var out []int
	add := func(pid int) {
		if pid > 0 && pid != os.Getpid() && !seen[pid] {
			seen[pid] = true
			out = append(out, pid)
		}
	}

	// pid 檔。**要先確認那個 pid 真的是它** —— pid 會被系統回收，照著一個
	// 過期的 pid 檔去殺，殺到的可能是使用者自己的程式。
	if raw, err := os.ReadFile(filepath.Join(home, "daemon.pid")); err == nil {
		line := strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
		if pid, err := strconv.Atoi(line); err == nil && looksLegacy(pid) {
			add(pid)
		}
	}
	if runtime.GOOS != "windows" {
		if out, err := exec.Command("pgrep", "-f", LegacyBinary()).Output(); err == nil {
			for _, l := range strings.Fields(string(out)) {
				if pid, err := strconv.Atoi(l); err == nil {
					add(pid)
				}
			}
		}
	}
	return out
}

// looksLegacy：這個 pid 的指令列看起來是不是舊版。
func looksLegacy(pid int) bool {
	if runtime.GOOS == "windows" {
		return true // tasklist 的比對在 stopPid 那邊做
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "args=").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "ava-local")
}
