//go:build darwin

package confine

import (
	"fmt"
	"time"
)

// macOS 用系統內建的 sandbox-exec（Seatbelt）。每一台 Mac 都有，
// 使用者什麼都不必裝 —— 這是這個平台最好的情況。
//
// 注意：sandbox-exec 被 Apple 標為 deprecated 很多年了（`man sandbox-exec`
// 自己就這麼寫），但它一直都在，而且 Chrome、Xcode 這些東西都還在用。
// 真的哪天被拿掉的話，下面那個 smoke 會失敗，於是這台機器會**照實**回報
// 自己沒有關押，而不是安靜地失去保護。

const noSandboxExec = "這台 Mac 上找不到 sandbox-exec（它本來是系統內建的）。" +
	"裝 Docker 或 Podman 之後改用 --sandbox container，可以換回沙盒。"

// smokeSandboxExec 真的跑一次，理由跟 Linux 那邊一樣（見 native_linux.go）：
// 執行檔在不在，跟它跑不跑得起來是兩件事。
//
// **這一段沒有在真的 Mac 上驗過**（開發機是 Linux）。形狀是照 sandbox-exec 的
// 介面寫的：-p 吃一段 profile 字串，`(allow default)` 是最寬鬆的合法 profile。
var smokeSandboxExec = func(bin string) error {
	if _, err := runWithTimeout(5*time.Second, bin, "-p", "(version 1)(allow default)", "/usr/bin/true"); err != nil {
		return probeErr(err)
	}
	return nil
}

func detectNative(look LookPath) (Kind, string, string) {
	bin, err := look("sandbox-exec")
	if err != nil {
		return KindNone, "", noSandboxExec
	}
	if err := smokeSandboxExec(bin); err != nil {
		return KindNone, "", fmt.Sprintf("這台 Mac 上的 sandbox-exec 跑不起來（%v）。", err)
	}
	return KindSandboxExec, bin, ""
}
