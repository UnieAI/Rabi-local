package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// 這一組測試把整條路真的跑一遍：真的起一個 HTTP 伺服器、真的下載、真的換掉
// 一個執行檔、真的把它叫起來。testdata 裡那兩份「執行檔」是 shell script，
// 一份換過去會活著、一份換過去馬上死 —— 後者是回滾那條路的主角。
//
// 需要 /bin/sh，所以 Windows 上跳過（驗簽那一組是純運算，三平台都跑）。

type harness struct {
	t        *testing.T
	home     string
	execPath string
	u        *Updater
	deps     *Deps

	mu     sync.Mutex
	exits  []int
	states []State
}

const oldVersion = "0.1.0"

// oldDaemon 是「現在跑著的那一版」：version 報得出 0.1.0，被叫起來就安靜結束。
const oldDaemon = "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo 0.1.0; exit 0; fi\nexit 0\n"

func newHarness(t *testing.T, manifestName string, tweak func(d *Deps)) *harness {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("這組測試要 /bin/sh")
	}
	home := t.TempDir()
	execPath := filepath.Join(home, "unieai-copilot-desktop")
	if err := os.WriteFile(execPath, []byte(oldDaemon), 0o755); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/machines/ava-local/releases/latest":
			http.ServeFile(w, r, filepath.Join("testdata", manifestName))
		case strings.HasPrefix(r.URL.Path, "/api/machines/ava-local/releases/0.2.1/"):
			http.ServeFile(w, r, filepath.Join("testdata", "artifact-linux-x64-dies"))
		case strings.HasPrefix(r.URL.Path, "/api/machines/ava-local/releases/0.2.0/"):
			http.ServeFile(w, r, filepath.Join("testdata", "artifact-linux-x64"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	h := &harness{t: t, home: home, execPath: execPath}
	yes := true
	d := Deps{
		Server:         srv.URL,
		CurrentVersion: oldVersion,
		Home:           home,
		ExecPath:       execPath,
		GOOS:           "linux",
		GOARCH:         "amd64",
		PublicKeyPEM:   testKey(t),
		// 測試裡的「執行檔」在暫存目錄底下，會被 looksLikeGoRun 擋掉 ——
		// 這裡明說允許，那道閘門另外測。
		AllowSelfReplace: &yes,
		IdlePoll:         5 * time.Millisecond,
		IdleWaitMax:      2 * time.Second,
		HandoverWait:     3 * time.Second,
		Log:              func(string, ...any) {},
		Exit: func(code int) {
			h.mu.Lock()
			h.exits = append(h.exits, code)
			h.mu.Unlock()
		},
		OnStatus: func(s Status) {
			h.mu.Lock()
			h.states = append(h.states, s.State)
			h.mu.Unlock()
		},
	}
	if tweak != nil {
		tweak(&d)
	}
	h.deps = &d
	h.u = New(d)
	return h
}

func (h *harness) execContents() string {
	h.t.Helper()
	raw, err := os.ReadFile(h.execPath)
	if err != nil {
		h.t.Fatalf("執行檔不見了：%v", err)
	}
	return string(raw)
}

func (h *harness) exitCodes() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]int(nil), h.exits...)
}

func (h *harness) sawState(s State) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, got := range h.states {
		if got == s {
			return true
		}
	}
	return false
}

func errCode(r OpResult) string {
	e, _ := r.Output["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func errMessage(r OpResult) string {
	e, _ := r.Output["error"].(map[string]any)
	msg, _ := e["message"].(string)
	return msg
}

/* ── 看有沒有新版 ─────────────────────────────────────────────────────── */

func TestCheckSeesNewVersion(t *testing.T) {
	h := newHarness(t, "good.manifest", nil)
	got := h.u.Check(context.Background())
	if !got.OK || !got.Available {
		t.Fatalf("應該看得到新版：%+v", got)
	}
	if got.LatestVersion != "0.2.0" || got.CurrentVersion != oldVersion {
		t.Errorf("版本不對：%+v", got)
	}
	// 更新說明要跟著回來，而且是**驗過簽章**的那一份 —— 網頁就是拿它給使用者看。
	if !strings.Contains(got.Notes, "退回舊版") {
		t.Errorf("更新說明沒帶回來：%q", got.Notes)
	}
}

// 別人的鑰匙簽的 manifest，連「有沒有新版」都不該回答。
func TestCheckRejectsOtherKey(t *testing.T) {
	h := newHarness(t, "other-key.manifest", nil)
	got := h.u.Check(context.Background())
	if got.OK || got.Available {
		t.Fatalf("不是我們簽的卻說有新版：%+v", got)
	}
	if got.Gate != GateSignature {
		t.Errorf("要說得出是哪一關：gate=%q reason=%q", got.Gate, got.Reason)
	}
}

/* ── 不裝的那些情況 ───────────────────────────────────────────────────── */

// 竄改過的 manifest 不會進到下載那一步，磁碟上的執行檔一個位元組都不動。
func TestApplyRejectsTamperedManifest(t *testing.T) {
	for _, name := range []string{"tampered-notes.manifest", "tampered-sha256.manifest", "other-key.manifest"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, name, nil)
			r := h.u.Apply(context.Background(), "")
			if r.OK {
				t.Fatalf("%s 竟然被接受了：%+v", name, r.Output)
			}
			if errCode(r) != "update_unavailable" || !strings.Contains(errMessage(r), "簽章") {
				t.Errorf("訊息要說得出是簽章那一關：code=%q msg=%q", errCode(r), errMessage(r))
			}
			if h.execContents() != oldDaemon {
				t.Error("執行檔被動過了")
			}
			if h.u.Status().State != StateFailed {
				t.Errorf("狀態應該是 failed，卻是 %q", h.u.Status().State)
			}
		})
	}
}

// **不做降版。** 簽章擋得住「裝一個我們沒發過的東西」，擋不住「裝一個我們
// 發過、但有已知漏洞的舊版本」。
func TestApplyRefusesOlderVersion(t *testing.T) {
	h := newHarness(t, "old.manifest", nil)
	r := h.u.Apply(context.Background(), "")
	if !r.OK {
		t.Fatalf("舊版本應該是「已經是最新的」而不是錯誤：%+v", r.Output)
	}
	if r.Output["upToDate"] != true || r.Output["accepted"] != false {
		t.Errorf("不該接受一個更舊的版本：%+v", r.Output)
	}
	if h.u.Status().State != StateUpToDate {
		t.Errorf("狀態應該是 up_to_date，卻是 %q", h.u.Status().State)
	}
	if h.execContents() != oldDaemon {
		t.Error("執行檔被動過了")
	}
}

func TestApplyRequiresManualReinstall(t *testing.T) {
	h := newHarness(t, "min-version.manifest", nil) // 0.3.0，minVersion 0.2.0，這台是 0.1.0
	r := h.u.Apply(context.Background(), "")
	if r.OK || errCode(r) != "manual_reinstall_required" {
		t.Fatalf("應該要求手動重裝：%+v", r.Output)
	}
	if h.execContents() != oldDaemon {
		t.Error("執行檔被動過了")
	}
}

// 雲端可以說「我按的是 0.2.0」，但它挑不了版本。
func TestApplyRejectsVersionMismatch(t *testing.T) {
	h := newHarness(t, "good.manifest", nil)
	r := h.u.Apply(context.Background(), "9.9.9")
	if r.OK || errCode(r) != "version_mismatch" {
		t.Fatalf("應該擋下指定版本：%+v", r.Output)
	}
}

/* ── 換檔、接手、退回 ─────────────────────────────────────────────────── */

func TestPerformUpdateInstalls(t *testing.T) {
	h := newHarness(t, "good.manifest", nil)
	m, err := h.u.FetchManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.u.PerformUpdate(context.Background(), m)

	if got := h.execContents(); !strings.Contains(got, "echo 0.2.0") {
		t.Fatalf("執行檔沒有被換成新版：%q", got)
	}
	// 舊的要留著 —— 退回那條路靠它。
	if _, err := os.Stat(h.execPath + ".old-" + oldVersion); err != nil {
		t.Errorf("舊的執行檔沒有留下來：%v", err)
	}
	out := ReadOutcome(h.home)
	if out == nil || out.Result != "installed" || out.To != "0.2.0" || out.From != oldVersion {
		t.Fatalf("沒有留下「剛剛換過版」的痕跡：%+v", out)
	}
	if codes := h.exitCodes(); len(codes) != 1 || codes[0] != 0 {
		t.Errorf("換完之後應該乾淨結束（exit 0），卻是 %v", codes)
	}
	// 暫存那一份已經搬到原位了，不該留著佔空間。
	if _, err := os.Stat(filepath.Join(h.home, "updates", "0.2.0")); !os.IsNotExist(err) {
		t.Errorf("暫存目錄沒清掉：%v", err)
	}
}

// 換過去之後才死掉的版本 —— 這正是回滾存在的理由。
func TestPerformUpdateRollsBack(t *testing.T) {
	h := newHarness(t, "dies.manifest", nil)
	m, err := h.u.FetchManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.u.PerformUpdate(context.Background(), m)

	if got := h.execContents(); got != oldDaemon {
		t.Fatalf("沒有退回舊版，現在原位上的是：%q", got)
	}
	out := ReadOutcome(h.home)
	if out == nil || out.Result != "rolled_back" {
		t.Fatalf("沒有留下「退回來了」的痕跡：%+v", out)
	}
	if out.To != "0.2.1" || out.From != oldVersion {
		t.Errorf("痕跡裡的版本不對：%+v", out)
	}
	st := h.u.Status()
	if st.State != StateFailed {
		t.Errorf("狀態應該是 failed，卻是 %q", st.State)
	}
	// 比「失敗了」更該說的一句話：那台電腦現在還好好的。
	if !strings.Contains(st.Message, "還是好好的") {
		t.Errorf("退回之後要告訴使用者他的電腦沒事，訊息卻是：%q", st.Message)
	}
	if !strings.Contains(st.Message, oldVersion) {
		t.Errorf("訊息要說得出退回到哪一版：%q", st.Message)
	}
	if codes := h.exitCodes(); len(codes) != 1 || codes[0] != 1 {
		t.Errorf("退回之後應該以 exit 1 結束，卻是 %v", codes)
	}
}

// 冒煙測試沒過就不換 —— 這時候原位上的還是舊的那一份，連備份都還沒產生。
func TestSmokeTestFailureKeepsOldBinary(t *testing.T) {
	h := newHarness(t, "dies.manifest", func(d *Deps) {
		// 拿 run 當「問版本」的參數，那份 script 會回 exit 3。
		d.VersionArgs = []string{"run"}
	})
	m, err := h.u.FetchManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.u.PerformUpdate(context.Background(), m)

	if h.execContents() != oldDaemon {
		t.Fatal("冒煙測試沒過卻還是換了")
	}
	if st := h.u.Status(); st.State != StateFailed || !strings.Contains(st.Error, "exit 3") {
		t.Errorf("要說得出新的執行檔怎麼了：%+v", st)
	}
	if len(h.exitCodes()) != 0 {
		t.Errorf("沒換成不該把自己收掉：%v", h.exitCodes())
	}
}

/* ── 等閒置 ───────────────────────────────────────────────────────────── */

// 手邊還有事的時候不換檔：換檔會殺掉這個行程，使用者看到的會是
// 「做到一半忽然斷了」，而且他永遠不會知道為什麼。
func TestWaitsForIdleBeforeSwapping(t *testing.T) {
	var mu sync.Mutex
	busy := 3
	h := newHarness(t, "good.manifest", func(d *Deps) {
		d.IsBusy = func() bool {
			mu.Lock()
			defer mu.Unlock()
			if busy > 0 {
				busy--
				return true
			}
			return false
		}
	})
	m, err := h.u.FetchManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.u.PerformUpdate(context.Background(), m)

	if !h.sawState(StateWaitingForIdle) {
		t.Error("忙的時候應該先停在 waiting_for_idle")
	}
	if got := h.execContents(); !strings.Contains(got, "echo 0.2.0") {
		t.Errorf("忙完之後應該換成新版：%q", got)
	}
}

// 一直都在忙的話就放棄這一次，而且什麼都不動。
func TestGivesUpWhenNeverIdle(t *testing.T) {
	h := newHarness(t, "good.manifest", func(d *Deps) {
		d.IsBusy = func() bool { return true }
		d.IdleWaitMax = 20 * time.Millisecond
	})
	m, err := h.u.FetchManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.u.PerformUpdate(context.Background(), m)

	if h.execContents() != oldDaemon {
		t.Fatal("一直在忙卻還是換了")
	}
	if st := h.u.Status(); st.State != StateFailed || !strings.Contains(st.Error, "忙") {
		t.Errorf("要說得出為什麼沒換：%+v", st)
	}
}

/* ── 其他閘門 ─────────────────────────────────────────────────────────── */

// go run 出來的暫存執行檔換不掉自己：換它沒有意義，而且會在開發者的暫存
// 目錄留下一個會自己上線的 daemon。
func TestRefusesToReplaceGoRunBinary(t *testing.T) {
	h := newHarness(t, "good.manifest", func(d *Deps) { d.AllowSelfReplace = nil })
	r := h.u.Apply(context.Background(), "")
	if r.OK || errCode(r) != "not_updatable" {
		t.Fatalf("應該拒絕換掉 go run 的暫存檔：%+v", r.Output)
	}
	if !looksLikeGoRun("/tmp/go-build123/b001/exe/desktop") {
		t.Error("go-build 路徑應該被認出來")
	}
	if looksLikeGoRun("/usr/local/bin/unieai-copilot-desktop") {
		t.Error("正常安裝路徑不該被誤判")
	}
}

func TestUpdateDisabledByEnv(t *testing.T) {
	t.Setenv("AVA_LOCAL_UPDATE_DISABLED", "1")
	h := newHarness(t, "good.manifest", nil)
	r := h.u.Apply(context.Background(), "")
	if r.OK || errCode(r) != "update_disabled" {
		t.Fatalf("關掉自動更新之後不該做任何事：%+v", r.Output)
	}
}

// HandleOp 是 main.go 的接線點：三個 op 認得，其他的要說「不是我的事」。
func TestHandleOp(t *testing.T) {
	h := newHarness(t, "good.manifest", nil)
	ctx := context.Background()

	r, handled := h.u.HandleOp(ctx, "updateStatus", nil)
	if !handled || !r.OK || r.Output["state"] != string(StateIdle) {
		t.Errorf("updateStatus：%v %+v", handled, r.Output)
	}
	r, handled = h.u.HandleOp(ctx, "updateCheck", nil)
	if !handled || r.Output["latestVersion"] != "0.2.0" || r.Output["available"] != true {
		t.Errorf("updateCheck：%v %+v", handled, r.Output)
	}
	r, handled = h.u.HandleOp(ctx, "updateApply", map[string]any{"version": "9.9.9"})
	if !handled || r.OK {
		t.Errorf("updateApply 應該把版本帶進去並被擋下：%v %+v", handled, r.Output)
	}
	if _, handled = h.u.HandleOp(ctx, "exec", nil); handled {
		t.Error("不是更新的 op 不該被這裡吃掉")
	}
}
