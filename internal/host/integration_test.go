package host

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/UnieAI/Rabi-local/internal/relay"
	"github.com/UnieAI/Rabi-local/internal/runner"
)

// integration_test.go —— 用**真的** runner 跑一次。
//
// 上面那些測試盯的是接線，但它們兩邊都是我寫的：替身照我以為的方式回答，於是
// 「兩層各自綠、鏈是斷的」這件事測不出來。這裡把 internal/runner 真的接上去，
// 真的 spawn 一個行程，真的等它的輸出走完整條路回來。
//
// 一條就夠 —— 這不是 runner 的測試，是「host 對 runner 的假設成不成立」的測試。

func realHost(t *testing.T) (*Host, string) {
	t.Helper()
	root := t.TempDir()
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	scope, err := runner.NewScope([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{
		Root: root, Scope: scope, MachineID: "m-1",
		Gate:        &acceptingGate{},
		NewCommands: func(e runner.ExecEvents) Commands { return runner.New(e) },
		Redaction:   true,
	})
	t.Cleanup(h.Close)
	return h, root
}

func TestARealCommandRunsAndItsOutputComesBackInOrder(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("這台機器上沒有 bash")
	}
	h, _ := realHost(t)

	rec := &recorder{}
	h.Dispatch(relay.Invoke{
		ID:       "inv-real",
		Op:       "exec",
		Args:     []byte(`{"command":"printf 'hello\n'; printf 'no-newline-tail'"}`),
		Approval: goodTicket,
	}, rec.emit)

	res := rec.final(t)
	exit := output(t, res)["exit"].(map[string]any)
	if exit["code"] != 0 {
		t.Fatalf("指令沒有正常結束：%v", exit)
	}

	var seen strings.Builder
	for _, r := range rec.all() {
		if r.Partial {
			seen.WriteString(r.Output.(map[string]any)["data"].(string))
		}
	}
	// 最後一段沒有換行的輸出**一定要在結果之前到**（Flush 的理由），否則模型
	// 看到的是一條沒有結果的指令。
	if seen.String() != "hello\nno-newline-tail" {
		t.Fatalf("輸出不完整：%q", seen.String())
	}
}

// 允許清單有沒有真的到得了子行程 —— 這一條只有真的 spawn 才問得出來。
func TestARealChildCannotSeeTheDaemonsSecrets(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("這台機器上沒有 bash")
	}
	t.Setenv("OPENAI_API_KEY", "sk-live-不該被看到")
	t.Setenv("AVA_LOCAL_APP_URL", "https://agent.unieai.com")

	h, _ := realHost(t)
	rec := &recorder{}
	h.Dispatch(relay.Invoke{
		ID:       "inv-env",
		Op:       "exec",
		Args:     []byte(`{"command":"echo [$OPENAI_API_KEY][$AVA_LOCAL_APP_URL][$HOME]"}`),
		Approval: goodTicket,
	}, rec.emit)
	rec.final(t)

	var seen strings.Builder
	for _, r := range rec.all() {
		if r.Partial {
			seen.WriteString(r.Output.(map[string]any)["data"].(string))
		}
	}
	got := strings.TrimSpace(seen.String())
	if strings.Contains(got, "sk-live") || strings.Contains(got, "agent.unieai.com") {
		t.Fatalf("祕密流進子行程了：%q", got)
	}
	if !strings.Contains(got, os.Getenv("HOME")) {
		t.Fatalf("該給的沒給，指令會找不到家目錄：%q", got)
	}
}

// 界外的 cwd 在**還沒 spawn 之前**就要被擋掉，而不是變成一個 spawn 失敗 ——
// 兩者在雲端的處置完全不同（一個要請使用者加授權，一個是他的電腦壞了）。
func TestARealExecOutsideTheGrantedFolderIsRefusedBeforeSpawning(t *testing.T) {
	h, _ := realHost(t)
	rec := &recorder{}
	h.Dispatch(relay.Invoke{
		ID:       "inv-escape",
		Op:       "exec",
		Args:     []byte(`{"command":"ls","cwd":"/etc"}`),
		Approval: goodTicket,
	}, rec.emit)
	if code := failureCode(t, rec.final(t)); code != "outside_root" {
		t.Fatalf("代碼應該是 outside_root，拿到 %q", code)
	}
}
