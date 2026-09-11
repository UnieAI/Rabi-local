//go:build windows

package confine

// Windows 沒有「不必安裝任何東西就能用」的關押。這個檔案存在是為了把那句話
// 寫在程式裡，而不是讓它變成一個沒有人講的空白。
//
// 為什麼不做：
//
//   - Restricted Token / Job Object / AppContainer 都要直接呼叫 Win32
//     （CreateRestrictedToken、CreateAppContainerProfile…）。那表示 cgo 或者
//     golang.org/x/sys/windows，前者會讓三平台交叉編譯變麻煩，後者是這個
//     模組目前唯一的外部相依 —— 兩個都不是「順手做一下」。
//   - 就算做了，AppContainer 底下大部分開發用的 toolchain 會直接壞掉
//     （node、python、git 對 profile 目錄的假設），於是使用者得到的是一個
//     不能跑測試的 agent。
//
// 所以這裡回 KindNone，並且給一條**真的可行**的路：裝 Docker Desktop 或
// Podman 之後用容器那一層（container.go）。那一層在 Windows 上是好的。
//
// 這不是暫時的實作缺口而是刻意的取捨，所以 posture 會照實說 "none" ——
// 使用者是照那個字決定要不要把敏感資料放進授權資料夾的。

const noWindowsNative = "Windows 目前沒有可用的內建關押方式。" +
	"裝 Docker Desktop 或 Podman 之後改用 --sandbox container，指令就會在沙盒裡跑，只掛載你授權的資料夾。"

func detectNative(look LookPath) (Kind, string, string) {
	return KindNone, "", noWindowsNative
}
