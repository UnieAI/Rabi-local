package host

import (
	"encoding/base64"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/UnieAI/Rabi-local/internal/canonical"
	"github.com/UnieAI/Rabi-local/internal/confine"
	"github.com/UnieAI/Rabi-local/internal/envguard"
	"github.com/UnieAI/Rabi-local/internal/redact"
	"github.com/UnieAI/Rabi-local/internal/relay"
	"github.com/UnieAI/Rabi-local/internal/runner"
)

// exec.go —— `exec` 與 `cancel`。
//
// 這是整個 daemon 上最危險的一條路，所以它上面疊著四道東西，順序不能換：
//
//  1. **核准票**（approval.go）—— 沒有票就不跑。這一版比 TS 版嚴：TS 用
//     classifyCommand 讓唯讀的指令自動跑，Go 這一側**還沒有那份分級規則**，
//     所以每一條指令都要票。少了分級只會讓人多按幾次允許；反過來（沒有分級
//     就自動放行）才是真的危險。見 doc.go。
//  2. **關押**（internal/confine）—— 寫入由作業系統關在授權資料夾裡。
//     Wrap 失敗**不可以**退回沒有關押的 argv。
//  3. **環境變數允許清單**（internal/envguard）—— 子行程拿不到這個
//     程式的連線憑證。
//  4. **出站遮蔽**（internal/redact）—— 祕密在離開這台電腦之前蓋掉，而且
//     **結束時一定要 Flush**。

// DefaultTimeout 是 frame 沒帶期限時，一條指令最多跑多久。跟 TS 版一樣兩分鐘。
const DefaultTimeout = 120 * time.Second

// execCall 是一條正在跑的指令。
//
// 一條輸出串流配一個遮蔽器：它要記住上一塊的尾巴，因為一把金鑰**會被切在兩塊
// 中間**，而那種漏法跟輸出的節奏有關，時好時壞，是最難發現的那一種。
// Stream 不是 goroutine-safe，而 runner 的 stdout 與 stderr 各跑在自己的
// goroutine 上 —— 所以兩條各一個，誰都不碰對方的。
type execCall struct {
	id      string
	command string
	actorID string

	out *redact.Stream
	err *redact.Stream

	partial func(any)
	done    chan relay.Result

	timedOut atomic.Bool
}

// execEvents 是交給 runner 的三個回呼。**在建構 Commands 的時候就要接上**，
// 所以 New 是用 NewCommands 工廠把它塞進去的。
func (h *Host) execEvents() runner.ExecEvents {
	return runner.ExecEvents{
		Stdout: func(id string, chunk []byte) { h.execChunk(id, "stdout", chunk) },
		Stderr: func(id string, chunk []byte) { h.execChunk(id, "stderr", chunk) },
		Exit:   func(id string, code int, signal, errMsg string) { h.execExit(id, code, signal, errMsg) },
	}
}

// execChunk 把一塊輸出遮蔽過之後送出去。
//
// 形狀是 `{stream, data}` —— cube/relay.mjs 直接讀這兩個欄位。包一個比較漂亮
// 的信封，兩邊都會編譯過，然後模型看到的是一條沒有任何輸出的指令。
func (h *Host) execChunk(id, stream string, chunk []byte) {
	c := h.lookupExec(id)
	if c == nil {
		return
	}
	r := c.out
	if stream == "stderr" {
		r = c.err
	}
	// 遮蔽器會留一段尾巴（一把金鑰可能被切在兩塊中間），所以這一次可以安全
	// 送出去的往往比收到的短，有時候是空的。
	if safe := r.PushBytes(chunk); safe != "" {
		c.partial(map[string]any{"stream": stream, "data": safe})
	}
}

// execExit 收尾：先把遮蔽器裡留著的尾巴吐乾淨，再把最終結果交出去。
//
// **順序就是這個函式存在的理由。** 不 Flush 的話，最後一段沒有換行結尾的輸出
// 會整段消失，而那通常正是指令真正的結果（`echo -n`、最後一行沒有換行的程式
// 很常見）。而 Flush 一定要在最終結果**之前**送出去，否則它會撞上一個已經被
// relay 刪掉的待辦然後靜靜消失。
//
// 這個函式跑在 runner 的收尾 goroutine 上，而 runner 保證它在兩條輸出都讀乾淨
// 之後才呼叫 —— 所以這裡碰遮蔽器不會跟 pump 打架。
func (h *Host) execExit(id string, code int, signal, errMsg string) {
	c := h.takeExec(id)
	if c == nil {
		return
	}
	if s := c.out.Flush(); s != "" {
		c.partial(map[string]any{"stream": "stdout", "data": s})
	}
	if s := c.err.Flush(); s != "" {
		c.partial(map[string]any{"stream": "stderr", "data": s})
	}
	// 蓋掉這件事本身要進稽核 —— 使用者事後要知道「那一次有東西沒送出去」。
	if kinds := redactedKinds(c.out, c.err); kinds != "" {
		h.audit("redact", "exec: "+kinds, "auto", c.actorID)
	}

	switch {
	case c.timedOut.Load():
		// 逾時不是失敗，是一個帶著記號的結束：模型要看得出「它被砍掉了」，
		// 而不是猜一個 exit code 的意思。
		c.done <- relay.Done(id, map[string]any{
			"exit": map[string]any{"code": nil, "signal": "SIGKILL", "timedOut": true},
		})
	case errMsg != "":
		// runner 在**起不來**的時候也走 Exit（code -1 加一句話）。那是一次
		// 拒絕，不是一次結束 —— 兩者在雲端的處置完全不同。
		h.audit("exec", c.command, "error", c.actorID)
		c.done <- relay.Fail(id, "spawn_failed", errMsg)
	default:
		out := map[string]any{"code": code}
		if signal != "" {
			out["signal"] = signal
		} else {
			out["signal"] = nil
		}
		c.done <- relay.Done(id, map[string]any{"exit": out})
	}
}

// exec 跑一條指令，並且擋到它結束為止。
func (h *Host) exec(inv relay.Invoke, args map[string]any, partial func(any)) relay.Result {
	if h.commands == nil {
		return relay.Fail(inv.ID, "exec_disabled", "這台電腦不提供執行指令的能力。")
	}
	command := strings.TrimSpace(argString(args, "command"))
	if command == "" {
		return relay.Fail(inv.ID, "bad_request", "exec 要帶 command")
	}
	kind := normaliseKind(argString(args, "kind"))
	rawCwd := argString(args, "cwd")
	env := argStringMap(args, "env")
	sandbox := argBool(args, "sandbox")

	// **票綁的是 frame 上原本那幾個字串**，所以要在 Resolve 之前算 subject
	// （見 approval.go 的 execSubject）。
	actionID, err := h.requireApproval(
		"exec",
		canonical.PayloadHash(execSubject(command, kind, rawCwd, env, sandbox)),
		inv.Approval,
		command,
	)
	if err != nil {
		code, msg := codeOf(err)
		return relay.Fail(inv.ID, code, msg)
	}

	cwd, escape := h.resolve(rawCwd)
	if escape != nil {
		return relay.Fail(inv.ID, escape.Code, escape.Message)
	}

	argv, ok := shellArgv(kind, command)
	if !ok {
		return relay.Fail(inv.ID, "no_shell", "這台電腦上找不到可以執行指令的 shell。")
	}

	// ── 關押 ───────────────────────────────────────────────────────────
	//
	// 原生那層（bwrap / sandbox-exec）是 ModeAlways：它幾乎不花成本，而等
	// agent 開口的結果就是幾乎每一條指令都沒有關押。容器那層是 on-request：
	// 起容器要時間，而且容器裡不一定有使用者專案要的 toolchain。
	spawnCwd := cwd
	if h.conf.When() == confine.ModeAlways || sandbox {
		cmd, werr := h.conf.Wrap(argv, confine.Options{Root: h.root, Cwd: cwd})
		if werr != nil {
			// **不可以退回沒有關押的 argv。** 使用者是照 posture 決定要不要把
			// 敏感資料放進那個資料夾的，安靜地失去圍籬正是最糟的那一種結果。
			h.audit("exec", command, "error", actionID)
			return relay.Fail(inv.ID, "confine_failed", "這台電腦關不住這條指令，所以沒有跑它："+werr.Error())
		}
		argv = cmd.Argv
		spawnCwd = cmd.Dir
	}

	c := &execCall{
		id:      inv.ID,
		command: command,
		actorID: actionID,
		out:     redact.NewStream(),
		err:     redact.NewStream(),
		partial: partial,
		done:    make(chan relay.Result, 1),
	}
	// **先登記再啟動。** runner 在起不來的時候會**同步**回報 Exit，而那一則要
	// 找得到這一次呼叫，否則它會被丟掉，然後這裡永遠等下去。
	h.mu.Lock()
	h.execs[inv.ID] = c
	h.mu.Unlock()

	h.audit("exec", command, "run", actionID)
	h.commands.Start(h.scope, runner.ExecRequest{
		ID:      inv.ID,
		Kind:    "raw", // argv 已經決定好了（可能被關押包過），不要讓 runner 再挑一次
		Command: argv[0],
		Args:    argv[1:],
		FullEnv: envguard.ChildEnvFromOS(env),
		Cwd:     spawnCwd,
		Stdin:   stdinBase64(args),
	})

	deadline := DefaultTimeout
	if inv.DeadlineMs > 0 {
		deadline = time.Duration(inv.DeadlineMs) * time.Millisecond
	}
	timer := time.AfterFunc(deadline, func() {
		c.timedOut.Store(true)
		// 砍掉整棵樹，然後**等 runner 照正常的路回報結束** —— 那條路才會先
		// Flush 遮蔽器。在這裡自己結案的話，最後一段輸出會跟結果賽跑。
		h.commands.Cancel(inv.ID)
	})
	defer timer.Stop()

	return <-c.done
}

// cancel 中止一條正在跑的指令。
//
// **用的是 invoke 的 id**，跟雲端登記它的那根釘子同一根（cube/relay.mjs 的
// invokeId）。送別的東西會匹配不到任何東西，回 {cancelled:false}，而行程繼續
// 在使用者的電腦上跑。
func (h *Host) cancel(inv relay.Invoke, args map[string]any) relay.Result {
	if h.commands == nil {
		return relay.Done(inv.ID, map[string]any{"cancelled": false})
	}
	target := argString(args, "id")
	if target == "" || h.lookupExec(target) == nil {
		return relay.Done(inv.ID, map[string]any{"cancelled": false})
	}
	h.commands.Cancel(target)
	return relay.Done(inv.ID, map[string]any{"cancelled": true})
}

/* ── 小工具 ───────────────────────────────────────────────────────────── */

func (h *Host) lookupExec(id string) *execCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.execs[id]
}

// takeExec 取出並移除 —— 一次呼叫只准結束一次。
func (h *Host) takeExec(id string) *execCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.execs[id]
	delete(h.execs, id)
	return c
}

// shellArgv 決定「跑這段文字」實際上要執行什麼。
//
// agent 送下來的一律是 bash 語法。Unix 上就是 bash；Windows 上沒有 bash，
// 除非裝了 WSL —— 找得到就用它（語法才對得上），找不到就退回 PowerShell 並讓
// 指令自己去失敗，而不是在這裡假裝成功。
//
// **這裡自己挑，而不是交給 runner 挑**：關押那一層要的是一份已經定案的 argv，
// 而讓兩個地方各挑一次的結果，是它們遲早會挑出不同的東西。
// （runner 內部的 shellFor 因此在這條路上用不到 —— 見 doc.go。）
func shellArgv(kind, command string) ([]string, bool) {
	if kind == "python" {
		for _, name := range []string{"python3", "python"} {
			if p, err := exec.LookPath(name); err == nil {
				return []string{p, "-c", command}, true
			}
		}
		return nil, false
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return []string{p, "-lc", command}, true
	}
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("powershell.exe"); err == nil {
			return []string{p, "-NoProfile", "-Command", command}, true
		}
	}
	if p, err := exec.LookPath("sh"); err == nil {
		return []string{p, "-lc", command}, true
	}
	return nil, false
}

// （`execEnv` 的變通已經拿掉：`runner.ExecRequest` 現在收得下一份**完整替換**
// 的環境（`FullEnv`），所以允許清單真的讓不該給的變數**不存在**，而不是
// 「存在但值是空的」—— 後者對任何一個「有設就用」的程式仍然是假的訊號，而且
// `env | grep` 看起來像祕密還在。規則本身在 internal/envguard。）

// stdinBase64 是要餵進去的標準輸入。
//
// 線路上是**原文**（cube/relay.mjs 送的是 `stdin: string`），而 runner 收的是
// base64 —— 這裡是那個轉換點。
func stdinBase64(args map[string]any) string {
	s, ok := args["stdin"].(string)
	if !ok || s == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// redactedKinds 是這一次總共蓋掉了哪幾種東西，寫進稽核用。
func redactedKinds(streams ...*redact.Stream) string {
	seen := map[redact.Kind]bool{}
	for _, s := range streams {
		for k := range s.Found() {
			seen[k] = true
		}
	}
	if len(seen) == 0 {
		return ""
	}
	names := make([]string, 0, len(seen))
	for k := range seen {
		names = append(names, string(k))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
