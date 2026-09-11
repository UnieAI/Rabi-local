package menubar

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 一個假的家：三個檔案，隨意組合，就是這個小工具會遇到的所有情況。
func home(t *testing.T, machine, state, pid string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if body == "" {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("machine.json", machine)
	write("state.json", state)
	write("daemon.pid", pid)
	return dir
}

const paired = `{"appUrl":"https://agent.dev.unieai.com","machineId":"bbb08178-5739-4c5a","label":"RoydeMacBook-Air",
  "grantedRoot":"/Users/royshih","accessToken":"a","refreshToken":"r","hmacKey":"k","sandbox":"direct"}`

func mine() string      { return `{"pid":` + itoa(os.Getpid()) + `}` }
func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

// **最容易說謊的那一條。** daemon 被 kill -9 的時候來不及改寫 state.json，
// 那個檔會永遠停在 online。畫面必須先看行程。
func TestDeadProcessBeatsAStaleOnlineState(t *testing.T) {
	h := home(t, paired, `{"link":"online","since":"2020-01-01T00:00:00Z"}`, `{"pid":999999}`)
	s := Read(h)
	if s.Running {
		t.Fatal("pid 999999 不可能活著")
	}
	if got := StatusOf(s, time.Now()).Title; got != "Not running" {
		t.Fatalf("行程死了卻說 %q", got)
	}
}

func TestConnectedSaysHowLong(t *testing.T) {
	since := time.Now().Add(-90 * time.Second).UTC().Format(time.RFC3339)
	h := home(t, paired, `{"link":"online","since":"`+since+`"}`, mine())
	got := StatusOf(Read(h), time.Now()).Title
	if got != "Connected · 1m" {
		t.Fatalf("想要 Connected · 1m，拿到 %q", got)
	}
}

func TestOfflineCarriesTheDaemonsOwnWords(t *testing.T) {
	h := home(t, paired, `{"link":"offline","lastError":"connect failed: HTTP 502"}`, mine())
	got := StatusOf(Read(h), time.Now()).Title
	if got != "Offline · connect failed: HTTP 502" {
		t.Fatalf("把原因吞掉了：%q", got)
	}
}

func TestNotPaired(t *testing.T) {
	s := Read(t.TempDir())
	if s.Paired {
		t.Fatal("什麼檔案都沒有卻說配對過了")
	}
	rows := Rows(s, time.Now())
	if len(rows) != 2 || rows[0].Text != "Not paired" {
		t.Fatalf("沒配對的下拉不該有機器資訊：%+v", rows)
	}
}

// roy：「沙盒有的話顯示出來 沒有就不顯示」。
func TestSandboxRowOnlyWhenThereIsOne(t *testing.T) {
	h := home(t, paired, `{"link":"online"}`, mine())
	for _, r := range Rows(Read(h), time.Now()) {
		if r.Key == "sandbox" {
			t.Fatalf("這台沒有沙盒，卻畫了一列：%q", r.Text)
		}
	}

	withBox := `{"appUrl":"https://x","machineId":"m","label":"L","grantedRoot":"/tmp",
	  "accessToken":"a","refreshToken":"r","hmacKey":"k","sandbox":"container","sandboxRuntime":"podman","sandboxImage":"debian:stable-slim"}`
	h2 := home(t, withBox, `{"link":"online"}`, mine())
	var found string
	for _, r := range Rows(Read(h2), time.Now()) {
		if r.Key == "sandbox" {
			found = r.Text
		}
	}
	if found != "Sandbox: podman · debian:stable-slim" {
		t.Fatalf("有沙盒卻沒照實寫：%q", found)
	}
}

func TestToggleSaysWhatPressingItDoes(t *testing.T) {
	running := home(t, paired, `{"link":"online"}`, mine())
	stopped := home(t, paired, `{"link":"online"}`, `{"pid":999999}`)
	get := func(dir string) string {
		for _, r := range Rows(Read(dir), time.Now()) {
			if r.Key == "toggle" {
				return r.Text
			}
		}
		return ""
	}
	if get(running) != "Pause" {
		t.Fatalf("在跑的時候按鈕應該是 Pause，拿到 %q", get(running))
	}
	if get(stopped) != "Start" {
		t.Fatalf("沒在跑的時候按鈕應該是 Start，拿到 %q", get(stopped))
	}
}

// 換資料夾**不可以把憑證洗掉**。這是這個檔案裡最貴的一條：machine.json 是
// 整份覆寫的，用結構去解再寫回去，這個小工具不認得的欄位就消失了 —— 而那幾個
// 欄位是這台電腦的身分。
func TestSetFolderKeepsEveryFieldItDoesNotKnowAbout(t *testing.T) {
	h := home(t, paired, `{"link":"online"}`, mine())
	target := t.TempDir()

	var stopped, started bool
	a := Actions{
		Home:  h,
		Run:   func(string, ...string) error { stopped = true; return nil },
		Spawn: func(string, ...string) error { started = true; return nil },
	}
	if err := a.SetFolder(target); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(h, "machine.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["grantedRoot"] != target {
		t.Fatalf("資料夾沒換成 %q：%v", target, m["grantedRoot"])
	}
	for _, k := range []string{"accessToken", "refreshToken", "hmacKey", "machineId", "appUrl"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("換個資料夾把 %s 弄丟了 —— 這台電腦的身分就沒了", k)
		}
	}
	if !stopped || !started {
		t.Fatal("換過邊界一定要重啟，否則跑著的那個還在用舊的")
	}
}

func TestSetFolderRefusesSomethingThatIsNotAFolder(t *testing.T) {
	h := home(t, paired, "", mine())
	f := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := Actions{Home: h, Run: func(string, ...string) error { return nil }, Spawn: func(string, ...string) error { return nil }}
	if err := a.SetFolder(f); err == nil {
		t.Fatal("把一個檔案當成授權資料夾收下了")
	}
}

// 裝了開機自啟就一定要走服務：直接 kill，launchd 幾秒後會把它拉回來，
// 而使用者看到的是「我按了暫停，它自己又亮了」。
func TestPauseGoesThroughTheServiceWhenThereIsOne(t *testing.T) {
	var viaService, viaKill bool
	a := Actions{
		Home:             t.TempDir(),
		Run:              func(string, ...string) error { viaKill = true; return nil },
		Spawn:            func(string, ...string) error { return nil },
		ServiceInstalled: func() bool { return true },
		ServiceStop:      func() error { viaService = true; return nil },
	}
	if err := a.Pause(); err != nil {
		t.Fatal(err)
	}
	if !viaService || viaKill {
		t.Fatal("裝了服務卻去 kill 行程 —— 它會被拉回來")
	}
}

func TestShortPathKeepsBothEnds(t *testing.T) {
	long := "/Users/royshih/Documents/work/clients/unieai/copilot-v2/runtime/apps/ava-local"
	got := short(long)
	if len(got) > 46 {
		t.Fatalf("縮得不夠短：%q", got)
	}
	if got[:4] != "/Use" && got[:1] != "~" {
		t.Fatalf("頭被吃掉了：%q", got)
	}
	if got[len(got)-9:] != "ava-local" {
		t.Fatalf("尾被吃掉了：%q", got)
	}
}
