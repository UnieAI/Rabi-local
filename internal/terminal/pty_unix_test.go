//go:build linux || darwin

package terminal

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRealPty 用**這台機器上真的虛擬終端機**跑一次完整的來回。
//
// 假的 PTY 測得到登記簿的規矩，測不到這個檔案存在的理由。這裡要證明的四件事，
// 每一件壞掉的時候都會變成「看起來開起來了、但它不是一個終端機」：
//
//  1. shell 真的坐在一個 tty 上（`tty` 回 /dev/pts/N，不是 "not a tty"）。
//  2. 它有**控制終端機**，所以 job control 是開的（`$-` 裡有 m）。
//  3. 改大小之後 `stty size` 跟著變。
//  4. 寫一個 0x03 進去，會被 line discipline 變成送給前景工作的 SIGINT ——
//     這就是使用者按 Ctrl-C。
func TestRealPty(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("這台機器沒有 /dev/ptmx")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("這台機器沒有 /bin/sh")
	}

	root := t.TempDir()
	svc := New(Options{
		Root:     root,
		Contain:  fixedScope{root},
		Approval: GateFunc(func(_, _, _ string) (string, error) { return "action", nil }),
		// $SHELL 在 CI 上可能是任何東西；sh 到處都在，而且行為可預測。
		Env:      []string{"SHELL=/bin/sh", "USER=tester", "PATH=" + os.Getenv("PATH")},
		Hostname: func() string { return "testbox" },
	})
	if !svc.Available() {
		t.Skip("這台機器開不了 PTY")
	}

	out := &transcript{}
	view, err := svc.Open(OpenRequest{TerminalID: "real", Cols: 80, Rows: 24, Approval: "ticket"}, out.emit)
	if err != nil {
		t.Fatalf("開不起來：%v", err)
	}
	defer svc.CloseAll()
	if view.PID <= 0 {
		t.Fatalf("沒有拿到 shell 的 pid：%+v", view)
	}

	// 1 & 2：坐在 tty 上，而且 job control 是開的。
	mustType(t, svc, "tty; case \"$-\" in *m*) echo JOBCONTROL;; esac\n")
	out.waitFor(t, "/dev/", 5*time.Second)
	out.waitFor(t, "JOBCONTROL", 5*time.Second)

	// 3：改大小，shell 自己也要看得到。
	if _, err := svc.Resize("real", 100, 40); err != nil {
		t.Fatalf("改不了大小：%v", err)
	}
	mustType(t, svc, "stty size\n")
	out.waitFor(t, "40 100", 5*time.Second)

	// 4：Ctrl-C 中斷前景工作，而且 shell 自己還活著。
	mustType(t, svc, "sleep 30\n")
	time.Sleep(300 * time.Millisecond)
	if _, err := svc.Signal("real", "SIGINT"); err != nil {
		t.Fatalf("送不出 SIGINT：%v", err)
	}
	mustType(t, svc, "echo AFTER_INTERRUPT\n")
	out.waitFor(t, "AFTER_INTERRUPT", 5*time.Second)

	// 結束：shell 走了，這一側要收到 exit，而且捲動內容還在。
	mustType(t, svc, "exit 5\n")
	ev := out.waitEvent(t, "exit", 5*time.Second)
	if ev.ExitCode == nil || *ev.ExitCode != 5 {
		t.Errorf("離開碼不對：%+v", ev)
	}
	replay, err := svc.Replay("real")
	if err != nil || !strings.Contains(string(replay), "AFTER_INTERRUPT") {
		t.Errorf("結束之後捲動內容應該還讀得到：%v / %q", err, replay)
	}
}

// TestRealPtyRefusesUnapproved —— 真的後端上，沒有票一樣開不了。
func TestRealPtyRefusesUnapproved(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("這台機器沒有 /dev/ptmx")
	}
	root := t.TempDir()
	svc := New(Options{Root: root, Contain: fixedScope{root}, Env: []string{"SHELL=/bin/sh"}})
	if _, err := svc.Open(OpenRequest{TerminalID: "x", Approval: "ticket"}, func(Event) {}); CodeOf(err) != CodeApprovalReq {
		t.Fatalf("沒有接驗證器就該一律拒絕，得到 %v", err)
	}
}

func mustType(t *testing.T, svc *Service, s string) {
	t.Helper()
	if _, err := svc.Input("real", []byte(s)); err != nil {
		t.Fatalf("打不進去 %q：%v", s, err)
	}
}

// transcript 把終端機說過的話累積起來，讓測試可以等某一段字出現。
type transcript struct {
	mu     sync.Mutex
	text   strings.Builder
	events []Event
}

func (t *transcript) emit(e Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, e)
	if e.Event == "data" {
		t.text.Write(e.Data)
	}
}

func (tr *transcript) waitFor(t *testing.T, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		tr.mu.Lock()
		got := tr.text.String()
		tr.mu.Unlock()
		if strings.Contains(got, want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	tr.mu.Lock()
	got := tr.text.String()
	tr.mu.Unlock()
	t.Fatalf("等不到 %q，終端機到目前為止說的是：\n%s", want, got)
}

func (tr *transcript) waitEvent(t *testing.T, kind string, within time.Duration) Event {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		tr.mu.Lock()
		for _, e := range tr.events {
			if e.Event == kind {
				tr.mu.Unlock()
				return e
			}
		}
		tr.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等不到 %s 事件", kind)
	return Event{}
}
