//go:build !linux && !darwin && !windows

package terminal

// 其他 unix（FreeBSD、OpenBSD…）開 pty 的 ioctl 各不相同，而我們一台都沒有拿來
// 測過。**誠實地說做不到**，而不是照抄一份沒有人驗證過的常數然後在別人的機器上
// 開出一個怪東西 —— TS 版在 Windows 上就是這樣選的。
func newPlatformBackend() (Backend, error) {
	return nil, errf(CodeUnsupported, "這個作業系統上還沒有支援互動式終端機。")
}
