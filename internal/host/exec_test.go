package host

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/UnieAI/Rabi-local/internal/confine"
	"github.com/UnieAI/Rabi-local/internal/envguard"
	"github.com/UnieAI/Rabi-local/internal/relay"
	"github.com/UnieAI/Rabi-local/internal/runner"
)

// exec_test.go —— exec 那條路上四道東西各自有沒有真的套上去。

/* ── 一、partial 必須在最終結果之前 ─────────────────────────────────────── */

// 這條在 2026-09-06 用真的機器付過代價：輸出與結束是兩個獨立的請求，誰先到沒有
// 人管；指令越快，結束越容易超車 —— 而 relay 在最終結果落地的當下就把待辦刪掉，
// 於是被超車的輸出撞上「找不到這個 id」被靜靜丟掉。五個 echo 連著跑，兩個的
// stdout 整段不見而 exit 仍然是 0。
func TestOutputLandsBeforeTheFinalResult(t *testing.T) {
	h := newHarness(t)
	h.cmds.onStart = func(f *fakeCommands, req runner.ExecRequest) {
		f.ev.Stdout(req.ID, []byte("第一行\n"))
		f.ev.Stdout(req.ID, []byte("第二行\n"))
		f.ev.Exit(req.ID, 0, "", "")
	}

	rec := h.call("exec", map[string]any{"command": "echo hi"}, goodTicket)
	all := rec.all()
	if len(all) != 3 {
		t.Fatalf("應該是兩則輸出加一個結果，拿到 %d 則", len(all))
	}
	// final() 自己就會斷言「最終結果之前沒有任何非 partial」，這裡再明確一次
	// 順序與內容 —— 模型讀到的世界就是這個順序。
	for i, want := range []string{"第一行\n", "第二行\n"} {
		if !all[i].Partial {
			t.Fatalf("第 %d 則應該是 partial", i)
		}
		if got := all[i].Output.(map[string]any)["data"]; got != want {
			t.Fatalf("第 %d 則的內容是 %q，應該是 %q", i, got, want)
		}
	}
	rec.final(t)
}

// 遮蔽器為了接住被切開的金鑰會留著一段尾巴。**不 Flush 的話最後一段永遠不會
// 被檢查，也永遠不會送出去** —— 而那通常正是指令真正的結果（`echo -n`、最後
// 一行沒有換行的程式很常見）。
func TestTheLastLineWithoutANewlineStillArrives(t *testing.T) {
	h := newHarness(t)
	h.cmds.onStart = func(f *fakeCommands, req runner.ExecRequest) {
		f.ev.Stdout(req.ID, []byte("沒有換行的結果"))
		f.ev.Exit(req.ID, 0, "", "")
	}

	rec := h.call("exec", map[string]any{"command": "echo -n x"}, goodTicket)
	var seen strings.Builder
	for _, r := range rec.all() {
		if r.Partial {
			seen.WriteString(r.Output.(map[string]any)["data"].(string))
		}
	}
	if seen.String() != "沒有換行的結果" {
		t.Fatalf("最後一段輸出不見了，只拿到 %q", seen.String())
	}
	rec.final(t)
}

/* ── 二、出站遮蔽 ─────────────────────────────────────────────────────── */

// 一把金鑰**會被切在兩塊中間**，而那種漏法跟輸出的節奏有關，時好時壞，是最難
// 發現的那一種。串流版的遮蔽器就是為了這件事存在的。
func TestASecretSplitAcrossTwoChunksIsStillMasked(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 36)
	h := newHarness(t)
	h.cmds.onStart = func(f *fakeCommands, req runner.ExecRequest) {
		// 前面刻意不寫 "token="：那會先命中 assignment 那條規則，於是測到的
		// 是別的東西，而「被切成兩半的金鑰」這件事沒有被驗到。
		f.ev.Stdout(req.ID, []byte("讀到了 "+secret[:10]))
		f.ev.Stdout(req.ID, []byte(secret[10:]+"\n"))
		f.ev.Exit(req.ID, 0, "", "")
	}

	rec := h.call("exec", map[string]any{"command": "cat .env"}, goodTicket)
	var seen strings.Builder
	for _, r := range rec.all() {
		if r.Partial {
			seen.WriteString(r.Output.(map[string]any)["data"].(string))
		}
	}
	rec.final(t)
	if strings.Contains(seen.String(), secret) {
		t.Fatalf("金鑰原樣送出去了：%q", seen.String())
	}
	if !strings.Contains(seen.String(), "[redacted:github-token]") {
		t.Fatalf("沒有留下看得懂的記號，模型會以為那裡本來就是空的：%q", seen.String())
	}
}

/* ── 三、關押 ─────────────────────────────────────────────────────────── */

// alwaysConfine 是一個永遠生效、而且看得出來有沒有被套上的關押。
type alwaysConfine struct {
	err error
}

func (c alwaysConfine) Name() string       { return "fake-jail" }
func (c alwaysConfine) When() confine.Mode { return confine.ModeAlways }
func (c alwaysConfine) Wrap(argv []string, opts confine.Options) (confine.Command, error) {
	if c.err != nil {
		return confine.Command{}, c.err
	}
	return confine.Command{Argv: append([]string{"jail", "--root", opts.Root}, argv...), Dir: opts.Cwd}, nil
}

func TestConfinementIsActuallyApplied(t *testing.T) {
	h := newHarnessWith(t, func(o *Options) { o.Confine = alwaysConfine{} })
	h.call("exec", map[string]any{"command": "echo hi"}, goodTicket)
	if got := h.cmds.lastStart(t).Command; got != "jail" {
		t.Fatalf("關押沒有套上去，真的跑的是 %q", got)
	}
}

// **Wrap 失敗不可以退回沒有關押的 argv。** 使用者是照 posture 決定要不要把敏感
// 資料放進那個資料夾的，安靜地失去圍籬正是最糟的那一種結果。
func TestAFailedWrapRefusesInsteadOfRunningUnconfined(t *testing.T) {
	h := newHarnessWith(t, func(o *Options) {
		o.Confine = alwaysConfine{err: errors.New("bwrap 起不來")}
	})
	rec := h.call("exec", map[string]any{"command": "echo hi"}, goodTicket)
	if code := failureCode(t, rec.final(t)); code != "confine_failed" {
		t.Fatalf("代碼應該是 confine_failed，拿到 %q", code)
	}
	if len(h.cmds.started) != 0 {
		t.Fatal("關不住卻還是跑了 —— 這正是「以為有保護，其實沒有」")
	}
}

// agent 開口要沙盒的時候，on-request 的關押也要生效。
func TestSandboxTrueTurnsOnAnOnRequestConfinement(t *testing.T) {
	onRequest := onRequestConfine{}
	h := newHarnessWith(t, func(o *Options) { o.Confine = onRequest })

	h.call("exec", map[string]any{"command": "echo hi"}, goodTicket)
	if h.cmds.lastStart(t).Command == "jail" {
		t.Fatal("沒有開口卻被關押了 —— on-request 的意思就是等它開口")
	}
	h.call("exec", map[string]any{"command": "echo hi", "sandbox": true}, goodTicket)
	if h.cmds.lastStart(t).Command != "jail" {
		t.Fatal("agent 開口要沙盒了，卻沒有被關押")
	}
}

type onRequestConfine struct{}

func (onRequestConfine) Name() string       { return "fake-container" }
func (onRequestConfine) When() confine.Mode { return confine.ModeOnRequest }
func (onRequestConfine) Wrap(argv []string, opts confine.Options) (confine.Command, error) {
	return confine.Command{Argv: append([]string{"jail"}, argv...), Dir: opts.Cwd}, nil
}

/* ── 四、環境變數 ─────────────────────────────────────────────────────── */

// 子行程不該看得到這個程式的憑證。允許清單在 internal/envguard，這裡測的是
// **它有沒有被接上**（規則寫好了沒接線，是這個專案最常出事的形狀）。
func TestTheChildDoesNotSeeTheDaemonsSecrets(t *testing.T) {
	env := envguard.ChildEnv([]string{
		"PATH=/usr/bin",
		"HOME=/home/roy",
		"AVA_LOCAL_APP_URL=https://agent.unieai.com",
		"OPENAI_API_KEY=sk-live-很貴的東西",
	}, nil)

	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if got["PATH"] != "/usr/bin" || got["HOME"] != "/home/roy" {
		t.Fatalf("該給的沒給，指令會找不到任何程式：%v", got)
	}
	// **不存在**，不是「存在但空的」。一個空字串對「有設就用」的程式仍然是
	// 假的訊號，而 `env | grep` 看起來也像祕密還在。
	for _, k := range []string{"OPENAI_API_KEY", "AVA_LOCAL_APP_URL"} {
		if _, present := got[k]; present {
			t.Fatalf("%s 還在子行程的環境裡：%v", k, got)
		}
	}
}

// 接線：host 真的把那份清單當成**完整替換**交給 runner。
//
// 少了 FullEnv 的話 runner 會給 os.Environ() 的全部，而這一層寫得再對也沒用。
func TestHostReplacesTheEnvironmentRatherThanLayeringOnIt(t *testing.T) {
	src, err := os.ReadFile("exec.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "FullEnv: envguard.ChildEnvFromOS(") {
		t.Fatal("沒有用 FullEnv —— 允許清單只蓋得住值，蓋不住「那個變數存在」")
	}
}

/* ── 五、逾時與取消 ───────────────────────────────────────────────────── */

// 逾時不是失敗，是一個**帶著記號**的結束：模型要看得出「它被砍掉了」，而不是
// 對著一個 exit code 自己編一套解釋。
func TestATimedOutCommandSaysSoInsteadOfLookingLikeAnExit(t *testing.T) {
	h := newHarness(t)
	h.cmds.onStart = func(f *fakeCommands, req runner.ExecRequest) { /* 什麼都不做，讓它逾時 */ }
	h.cmds.onCancel = func(f *fakeCommands, id string) { f.ev.Exit(id, -1, "SIGKILL", "") }

	rec := &recorder{}
	args, _ := json.Marshal(map[string]any{"command": "sleep 999"})
	h.host.Dispatch(relay.Invoke{ID: "inv-1", Op: "exec", Args: args, Approval: goodTicket, DeadlineMs: 30}, rec.emit)

	exit := output(t, rec.final(t))["exit"].(map[string]any)
	if exit["timedOut"] != true {
		t.Fatalf("逾時的結果沒有帶記號：%v", exit)
	}
	if len(h.cmds.cancelled) == 0 {
		t.Fatal("逾時了卻沒有把行程砍掉 —— 它會留在使用者的電腦上")
	}
}

// cancel 用的是**invoke 的 id**，跟雲端登記它的那根釘子同一根。送別的東西會
// 匹配不到任何東西，而行程繼續在使用者的電腦上跑。
func TestCancelFindsTheCommandByItsInvokeID(t *testing.T) {
	h := newHarness(t)
	started := make(chan struct{})
	release := make(chan struct{})
	h.cmds.onStart = func(f *fakeCommands, req runner.ExecRequest) {
		go func() {
			close(started)
			<-release
			f.ev.Exit(req.ID, 0, "", "")
		}()
	}
	go func() {
		args, _ := json.Marshal(map[string]any{"command": "sleep 1"})
		h.host.Dispatch(relay.Invoke{ID: "exec-77", Op: "exec", Args: args, Approval: goodTicket}, func(relay.Result) {})
	}()
	<-started

	rec := h.call("cancel", map[string]any{"id": "exec-77"}, "")
	if output(t, rec.final(t))["cancelled"] != true {
		t.Fatal("取消一條正在跑的指令卻說沒有取消")
	}
	close(release)
}

/* ── 六、起不來要長得像拒絕，不是像一次結束 ───────────────────────────── */

func TestASpawnFailureIsARefusalNotAnExit(t *testing.T) {
	h := newHarness(t)
	h.cmds.onStart = func(f *fakeCommands, req runner.ExecRequest) {
		f.ev.Exit(req.ID, -1, "", "這台電腦上找不到 bash")
	}
	rec := h.call("exec", map[string]any{"command": "echo hi"}, goodTicket)
	if code := failureCode(t, rec.final(t)); code != "spawn_failed" {
		t.Fatalf("代碼應該是 spawn_failed，拿到 %q", code)
	}
}

/* ── 工具 ─────────────────────────────────────────────────────────────── */

// newHarnessWith 是 newHarness，但可以改一兩個 Options。
func newHarnessWith(t *testing.T, tweak func(*Options)) *harness {
	t.Helper()
	root := t.TempDir()
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	scope, err := runner.NewScope([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t: t, root: root,
		cmds:    &fakeCommands{onStart: exitAtOnce(0)},
		term:    &fakeTerminals{available: true},
		mcp:     &fakeMCP{available: true},
		devices: &fakeDevices{},
		updater: &fakeUpdater{},
		gate:    &acceptingGate{},
	}
	opts := Options{
		Root: root, Scope: scope, MachineID: "m-1", Gate: h.gate,
		NewCommands: func(e runner.ExecEvents) Commands { h.cmds.ev = e; return h.cmds },
		Terminals:   h.term, MCP: h.mcp, DeviceStore: h.devices, Update: h.updater,
		Redaction: true,
	}
	tweak(&opts)
	h.host = New(opts)
	return h
}
