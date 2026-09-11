package host

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/UnieAI/Rabi-local/internal/relay"
	"github.com/UnieAI/Rabi-local/internal/runner"
)

// dispatch_test.go —— 二十一個 op 有沒有真的接上去。
//
// 這一組測試盯的不是「那個 op 做得對不對」（那是六個功能套件自己的測試在守的），
// 是**接線**：每一個 op 有沒有走到該走的地方、帶著該帶的東西、失敗的時候回得出
// 一個機器分得出來的代碼。這一層曾經是這個專案最常出事的地方 ——
// 「兩層各自綠、鏈是斷的」。

type harness struct {
	t        *testing.T
	host     *Host
	root     string
	cmds     *fakeCommands
	term     *fakeTerminals
	mcp      *fakeMCP
	devices  *fakeDevices
	updater  *fakeUpdater
	gate     *acceptingGate
	auditLog []string
}

// newHarness 接一台什麼都有的機器：每一個協作者都是替身，授權資料夾是一個
// 真的暫存目錄（檔案那幾個 op 要真的碰磁碟才測得出東西）。
func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	// macOS 的 TempDir 是 /var 底下的 symlink，而 Scope 比的是解析過的路徑。
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	scope, err := runner.NewScope([]string{root})
	if err != nil {
		t.Fatalf("授權範圍建不起來：%v", err)
	}

	h := &harness{
		t:       t,
		root:    root,
		cmds:    &fakeCommands{onStart: exitAtOnce(0)},
		term:    &fakeTerminals{available: true},
		mcp:     &fakeMCP{available: true},
		devices: &fakeDevices{},
		updater: &fakeUpdater{},
		gate:    &acceptingGate{},
	}
	h.host = New(Options{
		Root:      root,
		Scope:     scope,
		MachineID: "m-1",
		Gate:      h.gate,
		NewCommands: func(e runner.ExecEvents) Commands {
			h.cmds.ev = e
			return h.cmds
		},
		Terminals:   h.term,
		MCP:         h.mcp,
		DeviceStore: h.devices,
		Update:      h.updater,
		Audit: func(op, detail, verdict, actionID string) {
			h.auditLog = append(h.auditLog, op+" "+verdict)
		},
		Redaction: true,
	})
	return h
}

// call 送一個 invoke 進去，回傳它送出去的每一則回報。
func (h *harness) call(op string, args map[string]any, approval string) *recorder {
	h.t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		h.t.Fatalf("args 序列化失敗：%v", err)
	}
	rec := &recorder{}
	h.host.Dispatch(relay.Invoke{ID: "inv-1", Op: op, Args: raw, Approval: approval}, rec.emit)
	return rec
}

/* ── 每一個 op 至少一條 ─────────────────────────────────────────────────── */

// 二十一個 op 都要走到它該走的地方。**清單寫死在這裡**，跟 protocol.mjs 的 OPS
// 一樣長 —— 加一個 op 而忘了接線，這個測試就會紅，而不是等到使用者按下去。
func TestEveryOpReachesItsCollaborator(t *testing.T) {
	ticket := goodTicket
	cases := []struct {
		op      string
		args    map[string]any
		approve bool
		check   func(t *testing.T, h *harness, rec *recorder)
	}{
		{op: "exec", args: map[string]any{"command": "echo hi"}, approve: true,
			check: func(t *testing.T, h *harness, rec *recorder) {
				if got := h.cmds.lastStart(t).Command; got == "" {
					t.Fatal("exec 沒有把任何東西交給 runner")
				}
				if _, ok := output(t, rec.final(t))["exit"]; !ok {
					t.Fatal("exec 的結果裡沒有 exit —— 雲端讀的就是這個欄位")
				}
			}},
		{op: "cancel", args: map[string]any{"id": "nope"},
			check: func(t *testing.T, h *harness, rec *recorder) {
				if output(t, rec.final(t))["cancelled"] != false {
					t.Fatal("取消一個不存在的 id 應該回 cancelled:false，不是失敗")
				}
			}},
		{op: "readFile", args: map[string]any{"path": "hello.txt"},
			check: func(t *testing.T, h *harness, rec *recorder) {
				out := output(t, rec.final(t))
				raw, _ := base64.StdEncoding.DecodeString(out["contentBase64"].(string))
				if string(raw) != "hi\n" {
					t.Fatalf("讀到的內容不對：%q", raw)
				}
			}},
		{op: "writeFile", args: map[string]any{"path": "new.txt", "contentBase64": base64.StdEncoding.EncodeToString([]byte("x"))}, approve: true,
			check: func(t *testing.T, h *harness, rec *recorder) {
				rec.final(t)
				if b, err := os.ReadFile(filepath.Join(h.root, "new.txt")); err != nil || string(b) != "x" {
					t.Fatalf("檔案沒有真的被寫出來：%v %q", err, b)
				}
			}},
		{op: "statFile", args: map[string]any{"path": "hello.txt"},
			check: func(t *testing.T, h *harness, rec *recorder) {
				if output(t, rec.final(t))["stat"] == nil {
					t.Fatal("statFile 對一個存在的檔案回了 null")
				}
			}},
		{op: "listFiles", args: map[string]any{"path": "."},
			check: func(t *testing.T, h *harness, rec *recorder) {
				if len(output(t, rec.final(t))["entries"].([]statEntry)) == 0 {
					t.Fatal("listFiles 什麼都沒列到")
				}
			}},
		{op: "deleteFile", args: map[string]any{"path": "hello.txt"}, approve: true,
			check: func(t *testing.T, h *harness, rec *recorder) {
				rec.final(t)
				if _, err := os.Stat(filepath.Join(h.root, "hello.txt")); !os.IsNotExist(err) {
					t.Fatal("檔案沒有被刪掉")
				}
			}},
		{op: "ensureDir", args: map[string]any{"path": "a/b"}, approve: true,
			check: func(t *testing.T, h *harness, rec *recorder) {
				rec.final(t)
				if st, err := os.Stat(filepath.Join(h.root, "a", "b")); err != nil || !st.IsDir() {
					t.Fatal("資料夾沒有被建出來")
				}
			}},
		{op: "terminalOpen", args: map[string]any{}, approve: true, check: expectTerminal("terminalOpen")},
		{op: "terminalInput", args: map[string]any{"id": "t1", "dataBase64": "aGk="}, check: expectTerminal("terminalInput")},
		{op: "terminalResize", args: map[string]any{"id": "t1", "cols": 80.0, "rows": 24.0}, check: expectTerminal("terminalResize")},
		{op: "terminalSignal", args: map[string]any{"id": "t1", "signal": "SIGINT"}, check: expectTerminal("terminalSignal")},
		{op: "terminalClose", args: map[string]any{"id": "t1"}, check: expectTerminal("terminalClose")},
		{op: "terminalReplay", args: map[string]any{"id": "t1"}, check: expectTerminal("terminalReplay")},
		{op: "mcpList", args: map[string]any{"server": "slidework"},
			check: func(t *testing.T, h *harness, rec *recorder) {
				rec.final(t)
				if len(h.mcp.listed) != 1 || h.mcp.listed[0] != "slidework" {
					t.Fatalf("mcpList 沒有把 server 帶下去：%v", h.mcp.listed)
				}
			}},
		{op: "mcpCall", args: map[string]any{"server": "slidework", "tool": "make_deck", "arguments": map[string]any{"n": 1.0}}, approve: true,
			check: func(t *testing.T, h *harness, rec *recorder) {
				rec.final(t)
				if len(h.mcp.calls) != 1 {
					t.Fatal("mcpCall 沒有走到本機 MCP")
				}
				if h.mcp.calls[0].Approval != goodTicket {
					t.Fatal("核准票沒有被帶下去 —— mcp 那一層才是判斷要不要票的地方")
				}
			}},
		{op: "updateCheck", args: map[string]any{}, check: expectUpdate("updateCheck")},
		{op: "updateApply", args: map[string]any{"version": "0.2.0"}, check: expectUpdate("updateApply")},
		{op: "updateStatus", args: map[string]any{}, check: expectUpdate("updateStatus")},
		{op: "deviceList", args: map[string]any{},
			check: func(t *testing.T, h *harness, rec *recorder) {
				out := output(t, rec.final(t))
				if _, ok := out["devices"]; !ok {
					t.Fatal("deviceList 沒有回 devices")
				}
				if out["deviceOnly"] != false {
					t.Fatal("一台還沒註冊過的機器不該說自己是 device-only")
				}
			}},
		{op: "deviceEnroll", args: map[string]any{"enrollment": "ZW5yb2xs"},
			check: func(t *testing.T, h *harness, rec *recorder) {
				rec.final(t)
				if len(h.devices.applied) != 1 {
					t.Fatal("deviceEnroll 沒有交給信任清單")
				}
			}},
	}

	if len(cases) != 21 {
		t.Fatalf("protocol.mjs 的 OPS 有 21 個，這裡只測了 %d 個", len(cases))
	}

	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			h := newHarness(t)
			if err := os.WriteFile(filepath.Join(h.root, "hello.txt"), []byte("hi\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			approval := ""
			if c.approve {
				approval = ticket
			}
			rec := h.call(c.op, c.args, approval)
			c.check(t, h, rec)
		})
	}
}

func expectTerminal(op string) func(*testing.T, *harness, *recorder) {
	return func(t *testing.T, h *harness, rec *recorder) {
		rec.final(t)
		if len(h.term.frames) != 1 || h.term.frames[0].Op != op {
			t.Fatalf("%s 沒有交給終端機那一層：%v", op, h.term.frames)
		}
	}
}

func expectUpdate(op string) func(*testing.T, *harness, *recorder) {
	return func(t *testing.T, h *harness, rec *recorder) {
		rec.final(t)
		if len(h.updater.ops) != 1 || h.updater.ops[0] != op {
			t.Fatalf("%s 沒有交給自動更新：%v", op, h.updater.ops)
		}
	}
}

/* ── 沒有票的會改東西動作要被拒絕 ─────────────────────────────────────── */

// 這是這一層最重要的一條：**沒有票就不做，而且沒有做**。
//
// 只檢查回了一個錯誤是不夠的 —— 真正要問的是「那件事有沒有已經發生了」。
func TestMutatingOpsRefuseWithoutATicket(t *testing.T) {
	cases := []struct {
		op   string
		args map[string]any
		// happened 回報那件事有沒有真的發生。
		happened func(h *harness) bool
	}{
		{"exec", map[string]any{"command": "rm -rf /"},
			func(h *harness) bool { return len(h.cmds.started) > 0 }},
		{"writeFile", map[string]any{"path": "x.txt", "contentBase64": "eA=="},
			func(h *harness) bool { _, err := os.Stat(filepath.Join(h.root, "x.txt")); return err == nil }},
		{"deleteFile", map[string]any{"path": "hello.txt"},
			func(h *harness) bool { _, err := os.Stat(filepath.Join(h.root, "hello.txt")); return err != nil }},
		{"ensureDir", map[string]any{"path": "made"},
			func(h *harness) bool { _, err := os.Stat(filepath.Join(h.root, "made")); return err == nil }},
	}

	for _, c := range cases {
		t.Run(c.op+"／沒附票", func(t *testing.T) {
			h := newHarness(t)
			os.WriteFile(filepath.Join(h.root, "hello.txt"), []byte("hi\n"), 0o600)
			rec := h.call(c.op, c.args, "")
			if code := failureCode(t, rec.final(t)); code != "approval_required" {
				t.Fatalf("代碼應該是 approval_required，拿到 %q", code)
			}
			if c.happened(h) {
				t.Fatal("被拒絕了，但那件事還是發生了")
			}
		})

		t.Run(c.op+"／票被拒", func(t *testing.T) {
			h := newHarness(t)
			os.WriteFile(filepath.Join(h.root, "hello.txt"), []byte("hi\n"), 0o600)
			rec := h.call(c.op, c.args, "ava1d.forged")
			if code := failureCode(t, rec.final(t)); code != "approval_rejected" {
				t.Fatalf("代碼應該是 approval_rejected，拿到 %q", code)
			}
			if c.happened(h) {
				t.Fatal("票被拒了，但那件事還是發生了")
			}
		})
	}
}

// **沒有注入閘門就是一律拒絕，不是一律放行。** 接線的人忘了那一行的時候，
// 這台機器要變成什麼都不做，而不是變成一台任何人都能叫它跑指令的電腦。
func TestNoGateMeansNothingMutatingRuns(t *testing.T) {
	root := t.TempDir()
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	scope, _ := runner.NewScope([]string{root})
	cmds := &fakeCommands{onStart: exitAtOnce(0)}
	h := New(Options{
		Root: root, Scope: scope, MachineID: "m-1",
		Gate:        nil, // ← 這就是被測的那一件事
		NewCommands: func(e runner.ExecEvents) Commands { cmds.ev = e; return cmds },
	})

	for _, op := range []string{"exec", "writeFile", "deleteFile", "ensureDir"} {
		rec := &recorder{}
		args, _ := json.Marshal(map[string]any{"command": "ls", "path": "a", "contentBase64": ""})
		// 連一張**看起來很像真的**的票都不該讓它跑：沒有閘門就是驗不了。
		h.Dispatch(relay.Invoke{ID: "i", Op: op, Args: args, Approval: goodTicket}, rec.emit)
		if code := failureCode(t, rec.final(t)); code != "approval_required" {
			t.Fatalf("%s：沒有閘門時應該回 approval_required，拿到 %q", op, code)
		}
	}
	if len(cmds.started) != 0 {
		t.Fatal("沒有閘門，卻還是有指令跑起來了")
	}
}

// 讀的那三個不要票 —— 那是使用者按「連接電腦」時就已經表達過的意思。
func TestReadOnlyOpsDoNotNeedATicket(t *testing.T) {
	h := newHarness(t)
	os.WriteFile(filepath.Join(h.root, "hello.txt"), []byte("hi\n"), 0o600)
	for _, c := range []struct{ op, path string }{
		{"readFile", "hello.txt"}, {"statFile", "hello.txt"}, {"listFiles", "."},
	} {
		rec := h.call(c.op, map[string]any{"path": c.path}, "")
		if res := rec.final(t); !res.OK {
			t.Fatalf("%s 不該要票，卻失敗了：%+v", c.op, res.Output)
		}
	}
}

/* ── 不認得的 op、壞掉的 args ───────────────────────────────────────────── */

// 雲端加一個新的 op 不該讓舊的 daemon 看起來像壞了 —— 它要說一句話，不是當掉。
func TestUnknownOpAnswersInsteadOfCrashing(t *testing.T) {
	h := newHarness(t)
	rec := h.call("teleport", map[string]any{}, "")
	res := rec.final(t)
	if code := failureCode(t, res); code != "unknown_op" {
		t.Fatalf("代碼應該是 unknown_op，拿到 %q", code)
	}
	f := res.Output.(relay.Failure)
	if f.Error.Message == "" {
		t.Fatal("錯誤訊息是空的 —— 使用者看到的就是這一句")
	}
}

// args 不是一個物件的時候要說得出「看不懂」，而不是在某個 type assert 上炸掉。
func TestMalformedArgsAnswerInsteadOfCrashing(t *testing.T) {
	h := newHarness(t)
	rec := &recorder{}
	h.host.Dispatch(relay.Invoke{ID: "i", Op: "readFile", Args: json.RawMessage(`"不是物件"`)}, rec.emit)
	if code := failureCode(t, rec.final(t)); code != "bad_request" {
		t.Fatalf("代碼應該是 bad_request，拿到 %q", code)
	}
}

// 沒有 args 的 op（deviceList）不該因為 args 是空的而失敗。
func TestEmptyArgsAreNotAnError(t *testing.T) {
	h := newHarness(t)
	rec := &recorder{}
	h.host.Dispatch(relay.Invoke{ID: "i", Op: "deviceList"}, rec.emit)
	if res := rec.final(t); !res.OK {
		t.Fatalf("deviceList 沒有參數就該成功：%+v", res.Output)
	}
}

// 一個沒有接住的 panic 會變成「那台機器忽然不回話了」——
// 一句跟真正的原因差很遠的話。接住它，回一個說得出口的錯誤，然後讓 daemon 活著。
func TestAPanicBecomesAnErrorNotSilence(t *testing.T) {
	root := t.TempDir()
	scope, _ := runner.NewScope([]string{root})
	h := New(Options{
		Root: root, Scope: scope,
		// 一個會炸的閘門：真實世界裡這會是某個沒想到的 nil。
		Gate: GateFunc(func(tool, ph, ap string) (string, error) { panic("閘門自己炸了") }),
	})
	rec := &recorder{}
	args, _ := json.Marshal(map[string]any{"path": "a", "contentBase64": ""})
	h.Dispatch(relay.Invoke{ID: "i", Op: "writeFile", Args: args, Approval: "t"}, rec.emit)
	if code := failureCode(t, rec.final(t)); code != "internal" {
		t.Fatalf("代碼應該是 internal，拿到 %q", code)
	}
}

/* ── 能力清單與 posture ─────────────────────────────────────────────────── */

// 宣傳一個一定會失敗的 op，比不宣傳更糟：使用者會按下去、等待、然後以為是
// 自己的電腦壞了。
func TestOpsOnlyAdvertiseWhatThisMachineCanReallyDo(t *testing.T) {
	h := newHarness(t)
	ops := h.host.Ops()
	has := func(op string) bool {
		for _, o := range ops {
			if o == op {
				return true
			}
		}
		return false
	}
	if !has("terminalOpen") || !has("mcpCall") || !has("deviceEnroll") || !has("updateCheck") || !has("exec") {
		t.Fatalf("該有的能力沒有被宣傳：%v", ops)
	}
	if has("cancel") {
		t.Fatal("cancel 不是一個能力，是 exec 的一部分 —— TS 版也不宣傳它")
	}

	// 換一台什麼都沒有的機器。
	bare := New(Options{Root: h.root})
	ops = bare.Ops()
	for _, op := range []string{"exec", "terminalOpen", "mcpList", "deviceList", "updateCheck"} {
		for _, o := range ops {
			if o == op {
				t.Fatalf("這台機器沒有 %s 的能力，卻宣傳了它", op)
			}
		}
	}
	// 檔案那六個永遠在：那是「連接電腦」這件事的最小意義。
	if len(ops) != 6 {
		t.Fatalf("一台什麼都沒有的機器應該只剩六個檔案 op，拿到 %v", ops)
	}
}

// hello 送的是**事實**，不是我們希望的狀態。
func TestHelloCarriesTheRealState(t *testing.T) {
	h := newHarness(t)
	hello := h.host.Hello()
	if hello.Machine.GrantedRoot != h.root {
		t.Fatalf("hello 說的授權資料夾不對：%q", hello.Machine.GrantedRoot)
	}
	if hello.Machine.DaemonVersion == "" {
		t.Fatal("hello 沒有帶版本 —— 雲端靠它說「你的 Rabi Local 太舊了」")
	}
	if hello.Machine.Posture.Confinement != "none" {
		t.Fatalf("沒有關押的時候要照實說 none，拿到 %q", hello.Machine.Posture.Confinement)
	}
	if !hello.Machine.Posture.OutboundRedaction {
		t.Fatal("這台 daemon 真的有出站遮蔽，posture 卻說沒有")
	}
	if len(hello.Machine.Posture.LocalMcpServers) == 0 {
		t.Fatal("授權過的本機 MCP 沒有出現在 posture 裡")
	}
	if hello.Machine.Posture.DeviceApproval.DeviceOnly {
		t.Fatal("一把金鑰都沒有的機器不該說自己是 device-only")
	}

	// 註冊一把之後，**同一份 posture 要立刻改口** —— 它是算出來的，不是開機
	// 時的快照。一台剛註冊完的機器如果一直說自己還沒受保護，使用者會以為
	// 註冊失敗了。
	h.call("deviceEnroll", map[string]any{"enrollment": "ZW5yb2xs"}, "")
	if !h.host.Hello().Machine.Posture.DeviceApproval.DeviceOnly {
		t.Fatal("註冊完了，posture 卻還說這台機器不是 device-only")
	}

	// 欄位名要跟 lib/machines/posture-checks.ts 吃的那一組一樣 —— 換一個字
	// 就是那一頭讀不到，而畫面上只會少一列，不會有任何錯誤。
	raw, _ := json.Marshal(hello.Machine.Posture)
	var got map[string]any
	json.Unmarshal(raw, &got)
	for _, key := range []string{"confinement", "confinementWhen", "grantedRoot", "outboundRedaction", "secretsHidden", "localMcpServers", "deviceApproval"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("posture 少了欄位 %q", key)
		}
	}
}

// 程式結束前每一種子行程都要被收掉：指令、終端機、MCP server。
// 不收的話它們會活過這個程式，而 relay 已經走了 —— 之後沒有人叫得動也殺得掉。
func TestCloseReapsEverySortOfChildProcess(t *testing.T) {
	h := newHarness(t)
	h.host.Close()
	if h.cmds.cancelAlls != 1 {
		t.Fatal("還在跑的指令沒有被收掉")
	}
	if h.term.closed != 1 {
		t.Fatal("終端機沒有被關掉 —— 一個活過 daemon 的 shell 沒有人殺得掉")
	}
	if h.mcp.closed != 1 {
		t.Fatal("本機 MCP server 沒有被收掉")
	}
}
