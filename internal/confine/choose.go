package confine

import "fmt"

// choose.go —— 這台機器實際上用哪一種關押，以及怎麼把那件事**照實**講出來。

// 偵測的三個接縫。Choose 不直接呼叫偵測函式，是為了讓測試驗得到「機器上
// 沒有 X 的時候會怎樣」—— 而那正是最需要被驗的幾條路（降級有沒有照實講）。
// 真的跑起來時它們就是同名的匯出函式。
var (
	detectNativeFn    = DetectNative
	detectContainerFn = DetectContainerRuntime
	hasImageFn        = HasImage
)

// Preference 是使用者（配對時的 --sandbox 旗標）表達的偏好。
//
// 偏好不等於結果：要求容器而這台機器沒有 docker，結果就不是容器。
// Choose 回傳的永遠是**實際發生的事**。
type Preference struct {
	// Mode "auto"（預設，空字串同義）、"container"、"off"。
	//
	//	auto       有原生關押就用（每一條指令都關），沒有就沒有
	//	container  用容器（等 agent 開口才關），沒有容器就退回 auto 的邏輯
	//	off        明著不要關押 —— 使用者自己的決定，我們照做並照實回報
	Mode string
	// Runtime 指定 docker 或 podman；空的話自動找。
	Runtime ContainerRuntime
	// Image 容器用哪個映像；空的話 DefaultImage。
	Image string
	// Network 容器的網路；空的話 "bridge"（留著網路，見 container.go）。
	Network string
	// User 容器裡用哪個 uid:gid 跑。
	User string
	// Home 覆寫家目錄（算憑證目錄用）。測試用；平常留空。
	Home string
	// Bin 覆寫關押程式的路徑。測試用；平常留空，由偵測填。
	Bin string
}

// Notice 是 Choose 的第二個回傳值：一句可以直接印給使用者看的話，
// 以及「這是不是降級」——工具列要不要亮黃燈、精靈要不要多說一句。
//
// 為什麼要強迫呼叫端拿到這個：一個相信自己被關押、實際上沒有的人，處境比
// 知道自己沒有的人更糟 —— 他會把敏感資料放進那個資料夾。安靜地退回
// 「沒有關押」是這個產品最不該做的事，所以降級一定帶著一句解釋。
type Notice struct {
	// Message 給人看的一句話（繁體中文）。
	Message string
	// Degraded 為 true 代表**沒有**拿到預期的關押（完全沒有，或比要求的弱）。
	Degraded bool
}

// Choose 決定這台機器要用哪一種關押。
//
// 回傳的 Confinement **永遠不是 nil**（最差是 Noop），所以呼叫端不必判斷；
// 但第二個回傳值一定要用掉 —— 開機那一行日誌、工具列、posture 都靠它說實話。
//
//	c, n := confine.Choose(confine.Preference{Mode: cfg.Sandbox})
//	fmt.Println(n.Message)
//	// hello:
//	p := confine.PostureOf(c, root, false)
func Choose(p Preference) (Confinement, Notice) {
	switch p.Mode {
	case "off":
		// 使用者明著關掉的。這不是 bug，但仍然是「沒有關押」，所以照實說 ——
		// 而且標成降級：工具列該讓他看得見自己現在是這個狀態。
		return Noop(), Notice{
			Degraded: true,
			Message:  "關押已關閉（--sandbox off）：指令直接在這台電腦上執行，寫到哪裡都沒有圍籬。",
		}
	case "container":
		rt := p.Runtime
		if rt == "" {
			if found, ok := detectContainerFn(); ok {
				rt = found
			}
		}
		if rt != "" {
			image := p.Image
			if image == "" {
				image = DefaultImage
			}
			c := NewContainer(ContainerOptions{Runtime: rt, Image: image, Network: p.Network, User: p.User})
			if !hasImageFn(rt, image) {
				// 映像沒拉下來不是「沒有關押」，是「agent 一要求沙盒就會失敗」。
				// 兩種都要講，因為補救方法不一樣。
				return c, Notice{
					Degraded: true,
					Message: fmt.Sprintf("沙盒可用（%s · %s），但映像還沒拉下來 —— 先跑 `%s pull %s`，"+
						"否則 agent 要求沙盒時會失敗。平常的指令仍然直接在這台電腦上執行。", rt, image, rt, image),
				}
			}
			return c, Notice{
				Message: fmt.Sprintf("指令預設直接在這台電腦上執行；agent 要求時才在沙盒裡跑（%s · %s），那時只掛載授權資料夾。", rt, image),
			}
		}
		// 要容器而這台機器沒有 —— 退回 auto 的邏輯，但要說清楚退了。
		c, n := chooseNative(p)
		n.Degraded = true
		n.Message = "找不到 docker 或 podman（你要求了 --sandbox container）。" + n.Message
		return c, n
	default:
		return chooseNative(p)
	}
}

// chooseNative 是 auto 的主體：有原生關押就用，沒有就照實說沒有。
func chooseNative(p Preference) (Confinement, Notice) {
	kind, bin, why := detectNativeFn()
	if kind == KindNone {
		return Noop(), Notice{
			Degraded: true,
			Message:  "指令直接在這台電腦上執行，沒有寫入圍籬。" + why,
		}
	}
	if p.Bin != "" {
		bin = p.Bin
	}
	c, err := NewNative(kind, NativeOptions{Bin: bin, Home: p.Home})
	if err != nil {
		// 偵測說有、建立卻失敗：這是程式的 bug，不是機器的狀態。
		// 一樣不可以安靜地當成「沒有關押」。
		return Noop(), Notice{
			Degraded: true,
			Message:  fmt.Sprintf("偵測到 %s 但建不起來（%v）；指令會直接在這台電腦上執行。", kind, err),
		}
	}
	return c, Notice{
		Message: fmt.Sprintf("寫入被限制在授權資料夾內（%s），憑證目錄連讀都擋；每一條指令都適用。", kind),
	}
}
