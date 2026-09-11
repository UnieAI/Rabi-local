// Package menubar 是 macOS 上方工具欄那個小工具的**內容**。
//
// # 為什麼內容和畫面要分開
//
// 畫它的那一半（systray）在 macOS 上是 Objective-C，只有在 Mac 上才編得起來，
// 也只有在 Mac 上才看得到。把「要顯示什麼、按下去會怎樣」寫在那裡，等於這一段
// 邏輯永遠沒有測試 —— 而它講的每一句都是事實宣告：這台電腦連著沒有、agent 能
// 動哪個資料夾、指令有沒有被關起來。那種句子要測得動。
//
// 所以這個檔是純資料：讀磁碟、算出該顯示的幾行，回傳。menubar_darwin.go 只負責
// 把它們掛到選單上。
//
// # 它讀的是誰的檔案
//
// **不是它自己的。** 使用者實際在跑的 daemon 是 bun 編出來的那一支
// （runtime/apps/ava-local），而這個小工具和它共用 ~/.unieai/ava-local：
//
//	machine.json  這台機器是誰、授權哪個資料夾、有沒有沙盒
//	state.json    連線狀態（daemon 每次狀態改變就覆寫）
//	daemon.pid    那個行程還活著嗎
//
// 「活著」一律看 pid，「連著」一律看 state.json。被 kill -9 的 daemon 來不及改寫
// 狀態檔，那個檔會永遠停在 online —— 兩邊各自回答自己說得準的那一件事。
package menubar

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Home 是 daemon 的家。跟 TS 那一支同一個規則（config.ts 的 daemonHome）。
func Home() string {
	if v := os.Getenv("AVA_LOCAL_HOME"); v != "" {
		return v
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".unieai", "ava-local")
	}
	return filepath.Join(h, ".unieai", "ava-local")
}

type machineFile struct {
	AppURL        string `json:"appUrl"`
	MachineID     string `json:"machineId"`
	Label         string `json:"label"`
	GrantedRoot   string `json:"grantedRoot"`
	Sandbox       string `json:"sandbox"`
	SandboxRuntim string `json:"sandboxRuntime"`
	SandboxImage  string `json:"sandboxImage"`
}

type stateFile struct {
	Link      string `json:"link"`
	Since     string `json:"since"`
	LastError string `json:"lastError"`
}

type pidFile struct {
	PID int `json:"pid"`
}

// Snapshot 是「現在是什麼情況」，一次讀完。
type Snapshot struct {
	Paired      bool
	Label       string
	AppURL      string
	MachineID   string
	GrantedRoot string
	// Sandbox 空字串 ＝ 這台電腦上沒有沙盒。**空的時候整列不要畫**
	// （roy: 「沙盒有的話顯示出來 沒有就不顯示」）。
	Sandbox string
	// Running 是那個行程活著嗎。
	Running bool
	PID     int
	// Link 是 state.json 說的連線狀態；Running 是 false 的時候它不算數。
	Link      string
	Since     time.Time
	LastError string
}

func readJSON(path string, into any) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, into) == nil
}

// Read 把三個檔案讀成一份 Snapshot。任何一個讀不到都不是錯誤 —— 沒配對、
// 沒在跑、剛裝好都會缺其中一兩個，而那些都是要顯示出來的狀態。
func Read(home string) Snapshot {
	var s Snapshot

	var m machineFile
	if readJSON(filepath.Join(home, "machine.json"), &m) && m.MachineID != "" && m.GrantedRoot != "" {
		s.Paired = true
		s.Label = m.Label
		s.AppURL = m.AppURL
		s.MachineID = m.MachineID
		s.GrantedRoot = m.GrantedRoot
		if m.Sandbox == "container" {
			rt := m.SandboxRuntim
			if rt == "" {
				rt = "docker"
			}
			s.Sandbox = rt
			if m.SandboxImage != "" {
				s.Sandbox = rt + " · " + m.SandboxImage
			}
		}
	}

	var p pidFile
	if readJSON(filepath.Join(home, "daemon.pid"), &p) {
		s.PID = p.PID
		s.Running = pidAlive(p.PID)
	}

	var st stateFile
	if readJSON(filepath.Join(home, "state.json"), &st) {
		s.Link = st.Link
		s.LastError = st.LastError
		if t, err := time.Parse(time.RFC3339, st.Since); err == nil {
			s.Since = t
		}
	}
	return s
}

// Status 是選單列上那一行，以及圖示要用哪一種。
type Status struct {
	// Title 是下拉裡的第一行。
	Title string
	// Tone: "ok" / "warn" / "off"。darwin 那一側用它挑圖示。
	Tone string
}

// StatusOf 決定那一句話。**先看行程，再看狀態檔** —— 見檔頭。
func StatusOf(s Snapshot, now time.Time) Status {
	if !s.Paired {
		return Status{Title: "Not paired", Tone: "off"}
	}
	if !s.Running {
		return Status{Title: "Not running", Tone: "off"}
	}
	switch s.Link {
	case "online":
		if !s.Since.IsZero() {
			return Status{Title: "Connected · " + since(s.Since, now), Tone: "ok"}
		}
		return Status{Title: "Connected", Tone: "ok"}
	case "connecting":
		return Status{Title: "Connecting", Tone: "warn"}
	case "revoked":
		return Status{Title: "Removed in the browser", Tone: "off"}
	case "offline":
		if s.LastError != "" {
			return Status{Title: "Offline · " + s.LastError, Tone: "warn"}
		}
		return Status{Title: "Offline, retrying", Tone: "warn"}
	}
	return Status{Title: "Starting", Tone: "warn"}
}

func since(from, now time.Time) string {
	d := now.Sub(from)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + "d"
	}
}

// Row 是下拉裡的一列。
type Row struct {
	// Key 讓 darwin 那一側認得該把哪一個 item 換掉，而不是每次重建整個選單
	// （重建會讓正在打開的選單閃一下）。
	Key string
	// Text 顯示的字。
	Text string
	// Enabled false ＝ 灰掉，只能看。
	Enabled bool
}

// Rows 是整份下拉的內容，由上到下。
//
// roy 要的四件事：機器名、授權資料夾（可以在這裡切換）、運行狀態（能開能暫停）、
// 沙盒有才顯示。沒有的東西**整列不要出現** —— 一列寫著「沙盒：無」比沒有那一列
// 更佔空間，而且會讓人以為那裡有東西可以設定。
func Rows(s Snapshot, now time.Time) []Row {
	st := StatusOf(s, now)
	rows := []Row{{Key: "status", Text: st.Title, Enabled: false}}

	if !s.Paired {
		rows = append(rows, Row{Key: "hint", Text: "Open the browser and press Connect my computer", Enabled: false})
		return rows
	}

	rows = append(rows, Row{Key: "machine", Text: s.Label, Enabled: false})
	rows = append(rows, Row{Key: "folder", Text: "Folder: " + short(s.GrantedRoot), Enabled: true})
	if s.Sandbox != "" {
		rows = append(rows, Row{Key: "sandbox", Text: "Sandbox: " + s.Sandbox, Enabled: false})
	}
	if s.Running {
		rows = append(rows, Row{Key: "toggle", Text: "Pause", Enabled: true})
	} else {
		rows = append(rows, Row{Key: "toggle", Text: "Start", Enabled: true})
	}
	rows = append(rows, Row{Key: "open", Text: "Open Rabi in the browser", Enabled: s.AppURL != ""})
	return rows
}

// short 把家目錄縮成 ~，長路徑從中間截掉 —— 選單列的下拉不能太寬，而路徑
// 最有資訊的是頭和尾。
func short(p string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" && strings.HasPrefix(p, h) {
		p = "~" + p[len(h):]
	}
	const max = 44
	if len(p) <= max {
		return p
	}
	return p[:18] + "…" + p[len(p)-(max-19):]
}
