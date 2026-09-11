// tray.go —— 工具列上那個小東西，三個平台共用的那一半。
//
// 這個檔**只做畫面**。要顯示什麼、按下去算什麼，全在 model.go 與 actions.go 的
// 純函式裡（那些有測試）。理由寫在 model.go 的檔頭：這一段講的每一句都是安全
// 相關的事實宣告，而那種句子要測得動。
//
// 三個平台差在三件事，各自一個檔：
//
//	service_*.go   有沒有「開機自啟」這種東西，以及怎麼停、怎麼起
//	chooser_*.go   挑資料夾的視窗長什麼樣
//	systray        macOS 用文字當標題，Windows 與 Linux 只能放圖示
package menubar

import (
	_ "embed"
	"os/exec"
	"runtime"
	"time"

	"fyne.io/systray"
)

// 三顆燈。綠＝連著、琥珀＝連線中或重試、灰＝沒在跑 —— 跟 `ava-local status`
// 的 ●◐○ 同一套語意，使用者不必學第二套。
//
//go:embed icons/ok.png
var iconOK []byte

//go:embed icons/warn.png
var iconWarn []byte

//go:embed icons/off.png
var iconOff []byte

//go:embed icons/ok.ico
var icoOK []byte

//go:embed icons/warn.ico
var icoWarn []byte

//go:embed icons/off.ico
var icoOff []byte

func iconFor(tone string) []byte {
	win := runtime.GOOS == "windows"
	switch tone {
	case "ok":
		if win {
			return icoOK
		}
		return iconOK
	case "warn":
		if win {
			return icoWarn
		}
		return iconWarn
	default:
		if win {
			return icoOff
		}
		return iconOff
	}
}

// macOS 的選單列放得下一個字元，而一個字元比一顆點好認 —— 它在深色與淺色
// 選單列上都一定看得見，不必準備兩套圖。
func glyph(tone string) string {
	switch tone {
	case "ok":
		return "●"
	case "warn":
		return "◐"
	default:
		return "○"
	}
}

// Run 開始畫。它不會回來，直到使用者按 Quit。
func Run(home string) {
	systray.Run(func() { onReady(home) }, func() {})
}

func onReady(home string) {
	applyTone("off")
	systray.SetTooltip("Rabi Local")

	// 固定的幾個 item。**不要每次都重建選單** —— 重建會讓正在打開的選單閃一下，
	// 而這個東西每兩秒更新一次。
	items := map[string]*systray.MenuItem{}
	for _, key := range []string{"status", "hint", "machine", "folder", "sandbox", "toggle", "open"} {
		it := systray.AddMenuItem("", "")
		it.Hide()
		items[key] = it
	}
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit", "Close this tray item. Rabi Local keeps running.")

	acts := Actions{
		Home:             home,
		Run:              DefaultRunner,
		Spawn:            DefaultSpawner,
		ServiceInstalled: serviceInstalled,
		ServiceStop:      serviceStop,
		ServiceStart:     serviceStart,
	}

	var current Snapshot
	draw := func() {
		s := Read(home)
		current = s
		now := time.Now()
		applyTone(StatusOf(s, now).Tone)

		shown := map[string]bool{}
		for _, r := range Rows(s, now) {
			it, ok := items[r.Key]
			if !ok {
				continue
			}
			it.SetTitle(r.Text)
			if r.Enabled {
				it.Enable()
			} else {
				it.Disable()
			}
			it.Show()
			shown[r.Key] = true
		}
		for key, it := range items {
			if !shown[key] {
				it.Hide()
			}
		}
	}
	draw()

	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for range tick.C {
			draw()
		}
	}()

	go func() {
		for range items["toggle"].ClickedCh {
			// 按下去之後立刻重畫，不要等下一個 tick —— 兩秒的沉默看起來像沒反應。
			if current.Running {
				_ = acts.Pause()
			} else {
				_ = acts.Start()
			}
			time.Sleep(400 * time.Millisecond)
			draw()
		}
	}()

	go func() {
		for range items["folder"].ClickedCh {
			picked := chooseFolder(current.GrantedRoot)
			if picked == "" {
				continue // 使用者按了取消
			}
			_ = acts.SetFolder(picked)
			time.Sleep(600 * time.Millisecond)
			draw()
		}
	}()

	go func() {
		for range items["open"].ClickedCh {
			if current.AppURL != "" {
				_ = openBrowser(current.AppURL)
			}
		}
	}()

	go func() {
		<-quit.ClickedCh
		systray.Quit()
	}()
}

// applyTone 讓那顆燈跟著狀態走。
//
// macOS 用文字（選單列放得下，而且深淺主題都看得見）；Windows 與 Linux 的
// 系統匣只吃圖示 —— **沒有圖示就等於那裡什麼都沒有**，使用者會以為程式沒開。
func applyTone(tone string) {
	if runtime.GOOS == "darwin" {
		systray.SetTitle(glyph(tone))
		return
	}
	systray.SetIcon(iconFor(tone))
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Run()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Run()
	default:
		return exec.Command("xdg-open", url).Run()
	}
}
