// Package host 是這台電腦的執行點：雲端送下來的每一個 invoke 都落在這裡，
// 而**由這裡、不是由雲端**決定它跑不跑。
//
// # 這個套件在做什麼
//
// 六個功能套件各自把一件事做好（關押、遮蔽、終端機、本機 MCP、自動更新、
// 裝置簽的核准），但它們彼此不認識，也都不知道線路長什麼樣子。這裡是把它們
// 接成 21 個 op 的地方，而接線本身有規矩：
//
//  1. **會改東西的動作沒有票就不做。** 沒有注入核准閘門時一律拒絕，不是一律
//     放行（見 approval.go）。
//  2. **partial 必須在最終結果之前落地。** relay 在最終結果落地的當下就把待辦
//     刪掉，被超車的輸出會撞上「找不到這個 id」然後靜靜消失。所以一次 invoke
//     的每一則回報都走呼叫端給的同一個 emit（relay.Client.Send 是一條照順序
//     的佇列），**不另開 goroutine 送最終結果**。
//  3. **exec 的輸出要過遮蔽，而且結束時一定要 Flush** —— 不 Flush 的話最後一段
//     永遠不會被檢查，也永遠不會送出去（見 exec.go）。
//  4. **關押要真的套上去**，而且 Wrap 失敗不可以退回沒有關押的 argv（見 exec.go）。
//  5. **hello 帶的是這台機器實際的能力與狀態**，不是我們希望的狀態。
//  6. **程式結束前把子行程收乾淨** —— 活過 daemon 的行程是沒有人殺得掉的行程。
//
// # 依賴都是注入的
//
// Options 上的每一個協作者都是介面或指標，**nil 就是「這台機器沒有這個能力」**
// ——那種情況下對應的 op 不會出現在 hello 的清單裡，雲端看到的是事實，而不是
// 一顆按下去才失敗的按鈕。測試因此可以塞假的服務進來，不必真的開 PTY、
// 不必真的起 MCP server。
package host

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/UnieAI/Rabi-local/internal/confine"
	"github.com/UnieAI/Rabi-local/internal/devicekeys"
	"github.com/UnieAI/Rabi-local/internal/mcp"
	"github.com/UnieAI/Rabi-local/internal/relay"
	"github.com/UnieAI/Rabi-local/internal/runner"
	"github.com/UnieAI/Rabi-local/internal/terminal"
	"github.com/UnieAI/Rabi-local/internal/update"
)

/* ── 協作者：全部是窄介面，真的型別自動滿足 ───────────────────────────── */

// Commands 是「跑一條指令」這件事。*runner.Runner 滿足它。
type Commands interface {
	Start(scope *runner.Scope, req runner.ExecRequest)
	Cancel(id string)
	CancelAll()
	Running() int
}

// NewCommands 建一個 Commands。**事件要在建構的時候就接上**（runner 是這個
// 形狀），所以這裡收的是工廠而不是現成的東西 —— 不然 host 會拿不到輸出。
type NewCommands func(runner.ExecEvents) Commands

// Terminals 是 host 需要終端機做的事。*terminal.Service 滿足它。
type Terminals interface {
	Dispatch(f terminal.Frame, emit func(map[string]any)) terminal.Result
	Ops() []string
	Available() bool
	CloseAll()
}

// LocalMCP 是 host 需要本機 MCP 做的事。*mcp.Host 滿足它。
type LocalMCP interface {
	HandleList(ctx context.Context, serverID string) mcp.Result
	HandleCall(ctx context.Context, req mcp.CallRequest) mcp.Result
	Available() bool
	ServerIDs() []string
	Close()
}

// Devices 是這台電腦的裝置金鑰信任清單。*devicekeys.Store 滿足它。
type Devices interface {
	List() []devicekeys.TrustedDevice
	DeviceOnly() bool
	DeviceOnlySince() string
	Unsafe() string
	Apply(enrollB64 string, by *devicekeys.Assertion) (op string, credentialID string, err error)
}

// Updater 是自動更新那三個 op。*update.Updater 滿足它。
type Updater interface {
	HandleOp(ctx context.Context, op string, args map[string]any) (update.OpResult, bool)
}

/* ── 建構 ─────────────────────────────────────────────────────────────── */

// Options 是接一個 Host 要給的東西。
//
// **每一個協作者都可以是 nil**，而 nil 的意思一律是「這台機器沒有這個能力」——
// 對應的 op 不會被宣傳，被叫到的話回一個說得清楚的錯誤。
type Options struct {
	// Root 是使用者授權的資料夾（列目錄的相對路徑、終端機的起點、關押的邊界
	// 都用它）。空的話這台機器什麼都做不了，而那也是事實。
	Root string
	// Scope 是路徑圍籬。**nil 等於沒有授權任何資料夾**，所有帶路徑的 op 都會
	// 被拒絕 —— 失敗的方向永遠是關起來。
	Scope *runner.Scope
	// MachineID 是這台機器的身分，票上的 machineId 要跟它一致。
	MachineID string

	// Gate 驗核准票。**nil 就是每一個會改東西的動作都拒絕**（見 approval.go）。
	Gate ApprovalGate

	// Confine 是作業系統關押。nil 當成 confine.Noop()。
	Confine confine.Confinement

	NewCommands NewCommands
	Terminals   Terminals
	MCP         LocalMCP
	DeviceStore Devices
	Update      Updater

	// Audit 記一筆。verdict 是 auto / run / refused / error 之一。
	// **這個 daemon 還沒有稽核檔**，所以預設是 nil（什麼都不記）——
	// 見 doc.go 的「需要補的公開介面」。
	Audit func(op, detail, verdict, actionID string)
	// Log 給人看的一句話。nil 就完全不講話。
	Log func(format string, a ...any)

	// Redaction 說這台 daemon 有沒有出站遮蔽，會照實出現在 hello 的 posture 裡。
	// 由接線的人給，而不是寫死成 true —— 照抄 true 的話畫面就會對使用者說謊。
	Redaction bool

	// DaemonVersion 回報給雲端的版本。空的話用 relay.Version。
	DaemonVersion string
}

// Host 是這台電腦的執行點。用 New 建，由 main.go 保管一份。
type Host struct {
	opts Options

	root      string
	scope     *runner.Scope
	machineID string
	gate      ApprovalGate
	conf      confine.Confinement

	commands  Commands
	terminals Terminals
	mcp       LocalMCP
	devices   Devices
	updater   Updater

	// execs 是正在跑的指令。**key 是 invoke 的 id** —— 雲端的 cancel 用同一根
	// 釘子找它（cube/relay.mjs 用 invokeId 登記，送別的東西會匹配不到任何東西，
	// 回 {cancelled:false}，而行程繼續在使用者的電腦上跑）。
	mu    sync.Mutex
	execs map[string]*execCall

	// inflight 是還沒回覆的 invoke 數 —— 也就是「這台電腦現在有沒有在替使用者
	// 做事」。自動更新靠它決定可不可以換檔。開著的終端機也算（terminalOpen 這
	// 一個 invoke 會一直掛到 shell 結束），而那正是我們要的：有人正在那個終端機
	// 裡打字的時候把 daemon 換掉，畫面上就是「忽然斷了」。
	inflight atomic.Int64
}

// New 接一個 Host。**不會失敗** —— 少一個協作者就是少一個能力，不是一個錯誤。
func New(opts Options) *Host {
	h := &Host{
		opts:      opts,
		root:      opts.Root,
		scope:     opts.Scope,
		machineID: opts.MachineID,
		gate:      opts.Gate,
		conf:      opts.Confine,
		terminals: opts.Terminals,
		mcp:       opts.MCP,
		devices:   opts.DeviceStore,
		updater:   opts.Update,
		execs:     map[string]*execCall{},
	}
	if h.conf == nil {
		h.conf = confine.Noop()
	}
	if opts.NewCommands != nil {
		h.commands = opts.NewCommands(h.execEvents())
	}
	return h
}

// TerminalGate 把一道閘接成 terminal.Options.Approval 要的形狀。
//
// 放在這裡而不是讓 main.go 自己寫：錯誤代碼要活著穿過 terminal 那一層，而那
// 是一個很容易漏、漏了之後只會表現成「使用者一直按一顆沒有用的允許鍵」的細節。
func TerminalGate(g ApprovalGate) terminal.ApprovalGate { return terminalGate(g) }

/* ── 能力與狀態 ───────────────────────────────────────────────────────── */

// Ops 是這台機器**真的做得到**的 op，送在 hello 裡。
//
// cancel 刻意不在裡面（跟 TS 版一致）：它不是一個能力，是 exec 的一部分。
//
// 終端機、本機 MCP、裝置金鑰那幾個只在真的有的時候才宣傳 —— 雲端那一側會照
// 這份清單決定要不要把功能亮出來，而**宣傳一個一定會失敗的 op 比不宣傳更糟**：
// 使用者會按下去、等待、然後以為是自己的電腦壞了。
func (h *Host) Ops() []string {
	ops := []string{}
	if h.commands != nil {
		ops = append(ops, "exec")
	}
	ops = append(ops, "readFile", "writeFile", "statFile", "listFiles", "deleteFile", "ensureDir")
	if h.terminals != nil && h.terminals.Available() {
		ops = append(ops, h.terminals.Ops()...)
	}
	if h.mcp != nil && h.mcp.Available() {
		ops = append(ops, "mcpList", "mcpCall")
	}
	if h.updater != nil {
		ops = append(ops, "updateCheck", "updateApply", "updateStatus")
	}
	if h.devices != nil {
		ops = append(ops, "deviceList", "deviceEnroll")
	}
	return ops
}

// DeviceApproval 是裝置簽的核准現在的狀態，給 hello 與 deviceList 共用。
type DeviceApproval struct {
	Enrolled   int     `json:"enrolled"`
	DeviceOnly bool    `json:"deviceOnly"`
	Since      *string `json:"since"`
	// Unsafe 是信任清單自己的問題（權限不對、JSON 壞了）。**要端出去**：
	// 使用者唯一看得到的地方是雲端的畫面，daemon 的 log 在他自己的機器上
	// 而他不會去看。
	Unsafe *string `json:"unsafe"`
}

// Posture 是這台機器**實際上**是什麼狀態，送在 hello 裡給網頁打勾用。
//
// 欄位名對齊 lib/machines/posture-checks.ts 吃的那一組（confine.Posture 已經
// 對好了前五個），這裡補上兩個 confine 說不出來的事實。
//
// 一個相信自己被關押、實際上沒有的人，處境比知道自己沒有的人更糟：他會把敏感
// 資料放進那個資料夾。所以這裡送的是**事實**，不是我們希望的狀態。
type Posture struct {
	confine.Posture
	// LocalMcpServers 是使用者**授權過**的本機 MCP server，不是「這台電腦上
	// 有什麼」—— 沒授權的不會出現在這裡，連精靈也看不到。
	LocalMcpServers []string `json:"localMcpServers"`
	// DeviceApproval 見 DeviceApproval。
	DeviceApproval DeviceApproval `json:"deviceApproval"`
}

// Posture 算一次現在的狀態。
//
// **每次呼叫都重算**，不是啟動時的快照：註冊裝置是執行中發生的事，寫成固定值
// 的話，一台剛註冊完的機器會一直在 hello 裡說自己還沒受保護，直到重開為止。
func (h *Host) Posture() Posture {
	p := Posture{
		Posture:         confine.PostureOf(h.conf, h.root, h.opts.Redaction),
		LocalMcpServers: []string{},
	}
	if h.mcp != nil {
		if ids := h.mcp.ServerIDs(); ids != nil {
			p.LocalMcpServers = ids
		}
	}
	if h.devices != nil {
		p.DeviceApproval = DeviceApproval{
			Enrolled:   len(h.devices.List()),
			DeviceOnly: h.devices.DeviceOnly(),
			Since:      nilIfEmpty(h.devices.DeviceOnlySince()),
			Unsafe:     nilIfEmpty(h.devices.Unsafe()),
		}
	}
	return p
}

// HelloMachine 是 hello 裡描述這台機器的那一段。
type HelloMachine struct {
	Platform      string `json:"platform"`
	Arch          string `json:"arch"`
	DaemonVersion string `json:"daemonVersion"`
	GrantedRoot   string `json:"grantedRoot"`
	// Sandbox 與 SandboxDetail 是**舊的兩個值**，留著是為了不打斷既有的讀取端。
	// 它們已經表達不了原生關押那一種了 —— 新的東西看 posture。
	Sandbox       string  `json:"sandbox"`
	SandboxDetail *string `json:"sandboxDetail"`
	Posture       Posture `json:"posture"`
}

// Hello 是連上之後要 POST 給 /api/machines/relay/hello 的那一份。
//
// 形狀由 relay/routes.mjs 的 handleRelayHello 決定：{ machine, ops }，少一邊
// 就是 400。畫面靠它說「這台機器現在是哪一種」。
type Hello struct {
	Machine HelloMachine `json:"machine"`
	Ops     []string     `json:"ops"`
}

// Hello 組出這一份。
func (h *Host) Hello() Hello {
	name := h.conf.Name()
	sandbox := "container"
	var detail *string
	if name == "none" {
		sandbox = "direct"
	} else {
		d := name
		detail = &d
	}
	version := h.opts.DaemonVersion
	if version == "" {
		version = relay.Version
	}
	return Hello{
		Machine: HelloMachine{
			Platform:      nodePlatform(runtime.GOOS),
			Arch:          nodeArch(runtime.GOARCH),
			DaemonVersion: version,
			GrantedRoot:   h.root,
			Sandbox:       sandbox,
			SandboxDetail: detail,
			Posture:       h.Posture(),
		},
		Ops: h.Ops(),
	}
}

// nodePlatform 把 Go 的 GOOS 翻成 node 的 platform()。
//
// **"windows" 不是 "win32"**，而雲端那一側是拿字串在比的
// （lib/machines/posture-checks.ts 的 `platform === "win32"`）。翻錯的症狀是
// Windows 使用者看到一句寫給 Linux 的建議。
func nodePlatform(goos string) string {
	if goos == "windows" {
		return "win32"
	}
	return goos
}

// nodeArch 把 Go 的 GOARCH 翻成 node 的 arch()。
func nodeArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "ia32"
	default:
		return goarch
	}
}

// Busy 回報這台電腦現在有沒有在替使用者做事。自動更新用它決定可不可以換檔。
func (h *Host) Busy() bool { return h.inflight.Load() > 0 }

// Close 把這個程式起過的每一個子行程收掉。**程式結束前一定要叫。**
//
// 不叫的話，那些指令、那些 shell、那些 MCP server 會活過這個程式 —— 而 relay
// 已經走了，所以之後沒有任何人叫得動、也殺得掉它們。
func (h *Host) Close() {
	if h.mcp != nil {
		h.mcp.Close()
	}
	if h.terminals != nil {
		h.terminals.CloseAll()
	}
	if h.commands != nil {
		h.commands.CancelAll()
	}
}

/* ── 分派 ─────────────────────────────────────────────────────────────── */

// Dispatch 執行一次 invoke，並且把這一次的**每一則回報**都交給 emit。
//
// # emit 的規矩
//
// partial 與最終結果走**同一個** emit，而且照呼叫的順序 —— relay 在最終結果
// 落地的當下就把待辦刪掉，被超車的輸出會撞上「找不到這個 id」然後靜靜消失
// （2026-09-06 實測：五個 echo 連著跑，兩個 stdout 整段不見而 exit 仍是 0）。
// relay.Client.Send 已經是一條照順序的佇列，所以這裡只要保證**呼叫順序**：
// 最終結果永遠是這個函式對 emit 的最後一次呼叫，而且不在別的 goroutine 上。
//
// # 這個函式會擋住
//
// exec 擋到指令結束、terminalOpen 擋到 shell 結束。呼叫端要在自己的 goroutine
// 裡叫它（relay.Client 本來就是這樣派送的）。
func (h *Host) Dispatch(inv relay.Invoke, emit func(relay.Result)) {
	if emit == nil {
		emit = func(relay.Result) {}
	}
	var once sync.Once
	settle := func(r relay.Result) { once.Do(func() { emit(r) }) }

	// 一個沒有接住的 panic 會變成「那台機器忽然不回話了」，而使用者看到的跟
	// 真正的原因差很遠。接住它，回一個說得出口的錯誤，然後讓 daemon 活著。
	defer func() {
		if p := recover(); p != nil {
			h.logf("op %s 出錯：%v", inv.Op, p)
			settle(relay.Fail(inv.ID, "internal", fmt.Sprintf("這台電腦處理 %s 的時候出錯了：%v", inv.Op, p)))
		}
	}()

	// 自動更新那三個不算「在替使用者做事」：它們自己就是在問／改 daemon，
	// 算進 in-flight 的話，等閒置就會等到自己。
	if !isUpdateOp(inv.Op) {
		h.inflight.Add(1)
		defer h.inflight.Add(-1)
	}

	args, err := decodeArgs(inv.Args)
	if err != nil {
		settle(relay.Fail(inv.ID, "bad_request", fmt.Sprintf("看不懂的 args：%v", err)))
		return
	}

	partial := func(v any) {
		emit(relay.Result{ID: inv.ID, OK: true, Output: v, Partial: true})
	}
	settle(h.run(inv, args, partial))
}

// run 把一個 op 送到它的處理函式。回傳最終結果。
func (h *Host) run(inv relay.Invoke, args map[string]any, partial func(any)) relay.Result {
	switch inv.Op {
	case "exec":
		return h.exec(inv, args, partial)
	case "cancel":
		return h.cancel(inv, args)

	case "readFile":
		return h.readFile(inv, args)
	case "writeFile":
		return h.writeFile(inv, args)
	case "statFile":
		return h.statFile(inv, args)
	case "listFiles":
		return h.listFiles(inv, args)
	case "deleteFile":
		return h.deleteFile(inv, args)
	case "ensureDir":
		return h.ensureDir(inv, args)

	case "terminalOpen", "terminalInput", "terminalResize", "terminalSignal", "terminalClose", "terminalReplay":
		return h.terminal(inv, args, partial)

	case "mcpList":
		return h.mcpList(inv, args)
	case "mcpCall":
		return h.mcpCall(inv, args)

	case "updateCheck", "updateApply", "updateStatus":
		return h.update(inv, args)

	case "deviceList":
		return h.deviceList(inv)
	case "deviceEnroll":
		return h.deviceEnroll(inv, args)
	}
	// 不認得的 op 要回得出一句話，不是當掉：雲端加一個新的 op 不該讓舊的
	// daemon 看起來像壞了。
	return relay.Fail(inv.ID, "unknown_op", fmt.Sprintf("這一版的 Rabi Local 沒有實作「%s」。", inv.Op))
}

/* ── terminal / mcp / update / 小工具 ──────────────────────────────────── */

// terminal 把六個 terminal* 轉給 internal/terminal。
//
// 那個套件自己就會驗核准票、擋界外的 cwd、把事件變成線路的形狀，所以這裡只做
// 兩件事：確認這台機器真的有終端機，以及把 partial 接上同一個 emit。
func (h *Host) terminal(inv relay.Invoke, args map[string]any, partial func(any)) relay.Result {
	if h.terminals == nil {
		return relay.Fail(inv.ID, terminal.CodeDisabled, "這台電腦的互動式終端機沒有啟用。")
	}
	res := h.terminals.Dispatch(terminal.Frame{
		ID: inv.ID, Op: inv.Op, Args: args, Approval: inv.Approval,
	}, func(p map[string]any) { partial(p) })
	return relay.Result{ID: inv.ID, OK: res.OK, Output: res.Output}
}

// mcpList 是唯讀的，所以不要票（跟列目錄同一級）。
func (h *Host) mcpList(inv relay.Invoke, args map[string]any) relay.Result {
	if h.mcp == nil {
		return relay.Fail(inv.ID, "mcp_disabled", "這台電腦沒有啟用本機 MCP。")
	}
	ctx, cancel := deadlineContext(inv.DeadlineMs)
	defer cancel()
	return fromMCP(inv.ID, h.mcp.HandleList(ctx, argString(args, "server")))
}

// mcpCall 的三道關（授權 → 核准 → 稽核）全部在 internal/mcp 裡，順序不能換。
//
// **雲端只說得出 server 的 id。** frame 上就算帶了 command / cwd / env，
// mcp.CallRequest 連欄位都沒有 —— 那不是漏掉，是那個型別在說這件事。
func (h *Host) mcpCall(inv relay.Invoke, args map[string]any) relay.Result {
	if h.mcp == nil {
		return relay.Fail(inv.ID, "mcp_disabled", "這台電腦沒有啟用本機 MCP。")
	}
	ctx, cancel := deadlineContext(inv.DeadlineMs)
	defer cancel()
	return fromMCP(inv.ID, h.mcp.HandleCall(ctx, mcp.CallRequest{
		Server:     argString(args, "server"),
		Tool:       argString(args, "tool"),
		Arguments:  argObject(args, "arguments"),
		Approval:   inv.Approval,
		DeadlineMs: inv.DeadlineMs,
	}))
}

// update 是自動更新那三個。**它們不要核准票**，因為擋得住這件事的是簽章不是票：
// daemon 只裝我們私鑰簽過的東西，而那把私鑰不在任何一台跑 app 的機器上。
func (h *Host) update(inv relay.Invoke, args map[string]any) relay.Result {
	if h.updater == nil {
		return relay.Fail(inv.ID, "unknown_op", fmt.Sprintf("這一版的 Rabi Local 沒有實作「%s」。", inv.Op))
	}
	ctx, cancel := deadlineContext(inv.DeadlineMs)
	defer cancel()
	out, handled := h.updater.HandleOp(ctx, inv.Op, args)
	if !handled {
		return relay.Fail(inv.ID, "unknown_op", fmt.Sprintf("這一版的 Rabi Local 沒有實作「%s」。", inv.Op))
	}
	return relay.Result{ID: inv.ID, OK: out.OK, Output: out.Output}
}

func fromMCP(id string, r mcp.Result) relay.Result {
	if r.OK {
		return relay.Done(id, r.Value)
	}
	if r.Err != nil {
		return relay.Fail(id, r.Err.Code, r.Err.Message)
	}
	return relay.Fail(id, "mcp_failed", "本機 MCP 沒有說明原因就失敗了。")
}

// deadlineContext 比雲端的期限**早一點**放棄。
//
// 兩邊同時到期的話，先講話的是 relay，而它只說得出「那台機器沒回應」——
// 使用者看到的是「我的電腦壞了」。早兩秒放棄，錯誤就會是這台 daemon 給的
// 那一句比較有用的話。
func deadlineContext(deadlineMs int64) (context.Context, context.CancelFunc) {
	d := DefaultTimeout
	if deadlineMs > 0 {
		d = time.Duration(deadlineMs) * time.Millisecond
	}
	if d > 2*time.Second {
		d -= 2 * time.Second
	}
	return context.WithTimeout(context.Background(), d)
}

func isUpdateOp(op string) bool {
	return op == "updateCheck" || op == "updateApply" || op == "updateStatus"
}

// decodeArgs 把 frame 上的 args 解成一個 map。
//
// **空的、null、解不開都不是錯誤的 args，是「沒有參數」** —— 一個 deviceList
// 本來就不帶東西，而把它變成 bad_request 只會讓使用者看到一個莫名其妙的失敗。
// 真的壞掉（不是物件）才回錯。
func decodeArgs(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return map[string]any{}, nil
	}
	return out, nil
}

func (h *Host) audit(op, detail, verdict, actionID string) {
	if h.opts.Audit != nil {
		h.opts.Audit(op, detail, verdict, actionID)
	}
}

func (h *Host) logf(format string, a ...any) {
	if h.opts.Log != nil {
		h.opts.Log(format, a...)
	}
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
