package menubar

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// Bin 是使用者實際在跑的那支 daemon。
//
// **這個小工具自己不當 daemon。** 它只是一個看板加兩顆按鈕；真正維持連線的
// 是安裝腳本裝下去的那支執行檔，而它們共用同一個家目錄。小工具自己再開一條
// 連線的話，那台電腦會有兩個 daemon 搶同一組憑證。
func Bin(home string) string {
	return filepath.Join(home, "bin", "ava-local")
}

// Runner 讓測試把「真的去執行」換掉。
type Runner func(name string, args ...string) error

// DefaultRunner 跑一個指令並等它結束。
func DefaultRunner(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// Spawner 把 daemon 丟到背景並且不等它。
type Spawner func(name string, args ...string) error

// DefaultSpawner 起一個跟這個小工具無關的行程 —— 關掉選單列的東西不該把
// 使用者的連線一起帶走。
func DefaultSpawner(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// Actions 是那兩顆按鈕會做的事。
type Actions struct {
	Home  string
	Run   Runner
	Spawn Spawner
	// ServiceInstalled 回答「這台電腦裝了開機自啟嗎」。裝了的話，開關一定
	// 要走服務：直接 kill 掉行程，launchd 的 KeepAlive 幾秒內就把它拉回來
	// —— 使用者按了暫停、看著它停了、然後它自己又亮了。
	ServiceInstalled func() bool
	// ServiceCtl 是 launchctl 那條路。
	ServiceStop  func() error
	ServiceStart func() error
}

// Pause 讓這台電腦離線，而且**要停得住**。
func (a Actions) Pause() error {
	if a.ServiceInstalled != nil && a.ServiceInstalled() && a.ServiceStop != nil {
		return a.ServiceStop()
	}
	return a.Run(Bin(a.Home), "stop")
}

// Start 讓它重新待命。
func (a Actions) Start() error {
	if a.ServiceInstalled != nil && a.ServiceInstalled() && a.ServiceStart != nil {
		return a.ServiceStart()
	}
	return a.Spawn(Bin(a.Home), "run")
}

// SetFolder 換掉 agent 能動的那個資料夾。
//
// # 為什麼是改檔案再重啟，而不是叫一支 API
//
// `grantedRoot` 是 daemon 啟動時讀進記憶體的邊界，每一個檔案工具都靠它擋界外
// 的路徑。跑著的時候換掉它，等於在一個已經開始的回合中間把圍籬移走 —— 半個
// 回合用舊的邊界、半個用新的。所以換法是：寫檔、把 daemon 停掉、再起來。
//
// 網頁那一側不需要另外通知：daemon 每次連上都會在 hello 裡回報 grantedRoot
// （transport.ts），所以重啟之後畫面上就是新的那個。這就是「雙方同步」的方向 ——
// 事實從機器流向雲端，不是反過來。
func (a Actions) SetFolder(path string) error {
	if path == "" {
		return errors.New("menubar: empty folder")
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errors.New("menubar: not a folder: " + path)
	}

	file := filepath.Join(a.Home, "machine.json")
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	// 整份解成 map 再改一個欄位：用結構去解的話，這個小工具不認得的欄位
	// （refreshToken、hmacKey…）會在寫回去的時候消失，而那等於把這台電腦的
	// 憑證刪掉。
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m["grantedRoot"] == path {
		return nil
	}
	m["grantedRoot"] = path
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, file); err != nil {
		return err
	}

	// 換過邊界就一定要重啟，否則跑著的那個還在用舊的。
	_ = a.Pause()
	return a.Start()
}
