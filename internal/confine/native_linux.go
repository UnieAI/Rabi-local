//go:build linux

package confine

import (
	"fmt"
	"time"
)

// Linux 用 bubblewrap（bwrap）。它不是每台機器都有，但很常見 ——
// flatpak 會帶，各家發行版也都有套件。沒有就照實說沒有，不要退回
// 一個「看起來有關押」的東西。

const noBwrap = "這台機器上找不到 bwrap。裝上之後重新啟動就會自動生效" +
	"（Debian/Ubuntu: apt install bubblewrap；Fedora: dnf install bubblewrap；Arch: pacman -S bubblewrap）。"

// smokeBwrap **真的跑一次** bwrap，而不是只看執行檔在不在。
//
// 為什麼要多這一步：Ubuntu 23.10 之後預設用 AppArmor 擋掉沒有特權的
// user namespace，有些機器也把 kernel.unprivileged_userns_clone 關掉。
// 那種機器上 bwrap 裝著、`--version` 也答得出來，但每一條真的指令都會
// 死在 "setting up uid map: Permission denied"。
//
// 只看執行檔在不在的話，結果是**每一條指令都失敗**，而使用者看到的是一個
// 壞掉的產品。跑一次要 40 毫秒，開機時做一次，值得。
var smokeBwrap = func(bin string) error {
	if _, err := runWithTimeout(5*time.Second, bin, "--ro-bind", "/", "/", "--dev", "/dev", "true"); err != nil {
		return probeErr(err)
	}
	return nil
}

func detectNative(look LookPath) (Kind, string, string) {
	bin, err := look("bwrap")
	if err != nil {
		return KindNone, "", noBwrap
	}
	if err := smokeBwrap(bin); err != nil {
		// 裝了但跑不起來 —— 這是一句要給使用者看的話，所以連原因一起講。
		return KindNone, "", fmt.Sprintf(
			"這台機器上有 bwrap，但它跑不起來（%v）。常見原因是核心禁止沒有特權的 user namespace"+
				"（Ubuntu 23.10 之後的 AppArmor 預設，或 kernel.unprivileged_userns_clone=0）。", err)
	}
	return KindBwrap, bin, ""
}
