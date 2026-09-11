// unieai-copilot-desktop —— 讓 copilot-v2 的 agent 在**你自己的電腦上**工作。
//
// 它做的事只有一件：主動撥一條線到你選的 copilot-v2，然後在你批准過的資料夾裡
// 執行指令、讀寫檔案。連線是這一側建立的，所以你的電腦不需要有公開位址、
// 不需要開 port、不需要在路由器上做任何設定。
//
// # 它要連到哪個 copilot-v2
//
// **從哪個網站按下「連接電腦」，就連到哪裡。** 公司地端的員工在
// `copilot.acme.internal` 上按，程式就指向公司那台；一般使用者在
// `agent.unieai.com` 上按，就指向雲端。
//
// 做法是配對深連結，而不是把網址燒進執行檔 —— 後者會讓每個客戶都需要一份
// 各自簽章的檔案。網頁開啟：
//
//	unieai-copilot://pair?server=https://copilot.acme.internal&code=ABCD-EFGH
//
// 作業系統把這個網址交給本程式，它就同時完成「設定伺服器」與「配對」兩件事。
// 沒走過這一步的話，預設指向 agent.unieai.com。
//
// # 這一版是 headless
//
// 工具列圖示要 cgo，而 cgo 會讓三平台交叉編譯變麻煩。先把協定與安全模型跑通，
// 圖示是下一步 —— 中間這個版本已經完整可用，只是狀態印在終端機而不是選單上。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/UnieAI/Rabi-local/internal/audit"
	"github.com/UnieAI/Rabi-local/internal/config"
	"github.com/UnieAI/Rabi-local/internal/confine"
	"github.com/UnieAI/Rabi-local/internal/devicekeys"
	"github.com/UnieAI/Rabi-local/internal/envguard"
	"github.com/UnieAI/Rabi-local/internal/host"
	"github.com/UnieAI/Rabi-local/internal/mcp"
	"github.com/UnieAI/Rabi-local/internal/redact"
	"github.com/UnieAI/Rabi-local/internal/relay"
	"github.com/UnieAI/Rabi-local/internal/runner"
	"github.com/UnieAI/Rabi-local/internal/terminal"
	"github.com/UnieAI/Rabi-local/internal/update"
)

// DefaultServer 是沒有任何設定時的落點。使用者先裝了程式、還沒去過任何網站
// 的情況會用到它。
const DefaultServer = "https://agent.unieai.com"

// URLScheme 是註冊給作業系統的協定名。macOS 寫在 .app 的 Info.plist、
// Windows 寫登錄檔、Linux 寫 .desktop —— 都是打包時的事。
const URLScheme = "unieai-copilot"

func main() {
	serverFlag := flag.String("server", "", "要連到哪一個 copilot-v2（覆寫設定檔）")
	addRoot := flag.String("allow", "", "授權一個資料夾給 agent 使用")
	listRoots := flag.Bool("roots", false, "列出目前授權的資料夾")
	flag.Parse()

	// `version` —— 自動更新的冒煙測試會拿**新下載的執行檔**跑這一個子命令，
	// 它必須印出乾淨的版本號並以 0 結束。沒有它的話，換版會一律停在
	// 「新的執行檔說它是…」而不換檔（安全的那一邊，但永遠不會更新）。
	// 放在讀設定之前：一個設定檔壞掉的機器，它的新執行檔照樣該通得過冒煙測試。
	for _, arg := range flag.Args() {
		if arg == "version" {
			fmt.Println(relay.Version)
			return
		}
	}

	cfg, err := config.Load()
	if err != nil {
		die("讀不到設定：%v", err)
	}

	// 被作業系統用深連結叫起來 —— argv 裡會有那個網址。
	for _, arg := range flag.Args() {
		if strings.HasPrefix(arg, URLScheme+"://") {
			if err := handleDeepLink(cfg, arg); err != nil {
				die("配對失敗：%v", err)
			}
			fmt.Println("配對完成，已連到", cfg.Server)
			return
		}
	}

	if *serverFlag != "" {
		cfg.SetServer(*serverFlag)
	}
	if cfg.Server == "" {
		cfg.Server = DefaultServer
	}

	if *addRoot != "" {
		if cfg.AddRoot(*addRoot) {
			fmt.Println("已授權：", *addRoot)
		} else {
			fmt.Println("本來就授權過了：", *addRoot)
		}
		must(cfg.Save())
		return
	}
	if *listRoots {
		if len(cfg.Roots) == 0 {
			fmt.Println("還沒有授權任何資料夾。")
		}
		for _, r := range cfg.Roots {
			fmt.Println(r)
		}
		return
	}

	must(cfg.Save())

	if cfg.DeviceToken == "" {
		fmt.Printf("還沒有配對。請到 %s 按「連接電腦」。\n", cfg.Server)
		os.Exit(1)
	}

	run(cfg)
}

// handleDeepLink 處理 unieai-copilot://pair?server=…&code=…
//
// server 一定要是 https —— 這個網址來自瀏覽器，而它決定了之後所有指令從哪裡來。
// 允許 http 等於允許同網段的人把一台機器導去他自己的伺服器。唯一的例外是
// localhost，開發時要用。
func handleDeepLink(cfg *config.Config, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Host != "pair" && u.Path != "/pair" && u.Opaque != "pair" {
		return fmt.Errorf("看不懂的連結：%s", raw)
	}
	q := u.Query()
	server := strings.TrimRight(q.Get("server"), "/")
	code := q.Get("code")
	if server == "" || code == "" {
		return fmt.Errorf("連結少了 server 或 code")
	}
	su, err := url.Parse(server)
	if err != nil {
		return err
	}
	if su.Scheme != "https" && !isLoopback(su.Hostname()) {
		return fmt.Errorf("伺服器網址必須是 https：%s", server)
	}

	cfg.SetServer(server)
	machineID := cfg.EnsureMachineID()
	label := cfg.EnsureLabel()

	token, err := completePairing(cfg.Server, code, machineID, label)
	if err != nil {
		return err
	}
	cfg.DeviceToken = token
	return cfg.Save()
}

func isLoopback(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// completePairing 用配對碼換一張長期憑證。
func completePairing(server, code, machineID, label string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"code": code, "machineId": machineID, "label": label,
		"os": osName(), "clientVersion": relay.Version,
	})
	req, err := http.NewRequest(http.MethodPost, server+"/api/desktop/pair/complete", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out struct {
		Token string `json:"token"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != http.StatusOK || out.Token == "" {
		if out.Error != "" {
			return "", fmt.Errorf("%s", out.Error)
		}
		return "", fmt.Errorf("伺服器回 HTTP %d", res.StatusCode)
	}
	return out.Token, nil
}

func osName() string {
	switch runtimeGOOS() {
	case "darwin":
		return "darwin"
	case "windows":
		return "windows"
	default:
		return "linux"
	}
}

// run 是這個程式真正的工作：接好每一個零件，撥一條線出去，然後把雲端送下來的
// 每一個 invoke 交給 internal/host。
//
// **這個函式只負責建構與委派。** 二十一個 op 怎麼做、要不要票、輸出要不要遮，
// 全部在 internal/host 裡 —— 把政策寫在接線的地方，是讓它慢慢分岔的最快方法。
func run(cfg *config.Config) {
	scope, err := runner.NewScope(cfg.Roots)
	if err != nil {
		die("授權範圍讀不到：%v", err)
	}
	if scope.Empty() {
		fmt.Println("提醒：還沒有授權任何資料夾，所有操作都會被拒絕。")
		fmt.Printf("      到 %s 選一個工作資料夾，或用 --allow <路徑>。\n", cfg.Server)
	}
	root := ""
	if roots := scope.Roots(); len(roots) > 0 {
		root = roots[0]
	}

	// ── 起跑前先看環境 ──────────────────────────────────────────────────
	//
	// 一個被改寫過的 *_BASE_URL 或 proxy 變數，可以無聲地把這台 daemon（以及它
	// 跑的每一個工具）導到別人的伺服器。那不是便利功能，那就是攻擊本身，所以
	// 這裡是「不確定就不跑」。
	//
	// 「這台機器上有供應商金鑰」只是警告：我們本來就不會把它傳給工具，那句話
	// 本身就是處置 —— 做成致命的話，一個裝了 OPENAI_API_KEY 的開發者會發現
	// daemon 根本啟動不了。
	if v := envguard.GuardStartup(cfg.Server, os.Environ()); len(v.Problems) > 0 {
		for _, p := range v.Problems {
			fmt.Println("⚠ 環境：", p)
		}
		if !v.OK {
			die("環境不安全，沒有啟動。")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── 關押：照實講這台機器實際上是哪一種 ──────────────────────────────
	//
	// Choose 一定回得出一個 Confinement（最差是 Noop），但第二個回傳值一定要
	// 用掉：一個相信自己被關押、實際上沒有的人，處境比知道自己沒有的人更糟。
	conf, notice := confine.Choose(confine.Preference{})
	fmt.Println(notice.Message)

	// ── 核准：這台電腦信任哪幾把裝置公鑰 ────────────────────────────────
	//
	// 清單存在使用者自己的電腦上，而且**不由雲端決定** —— 那是「雲端偽造不出
	// 核准」這句話成立的唯一理由。讀不得的時候 Store 仍然回得出東西，但它的
	// Unsafe() 非空，而那會讓整台機器的核准停擺（devicekeys.Gate 自己會處理）。
	devices := devicekeys.Open(devicekeys.StoreOptions{
		File:      devicekeys.FileIn(config.Dir()),
		MachineID: cfg.MachineID,
		Logf:      func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	})
	if unsafe := devices.Unsafe(); unsafe != "" {
		fmt.Println("⚠ 裝置信任清單有問題，這台機器的核准全部停擺：", unsafe)
	}
	gate := host.DeviceGate{
		Gate:      devicekeys.NewGate(devicekeys.GateOptions{Store: devices, MachineID: cfg.MachineID}),
		MachineID: cfg.MachineID,
	}

	logf := func(format string, a ...any) { fmt.Printf(format+"\n", a...) }

	// ── 稽核：做過什麼，在使用者自己的電腦上留一份 ──────────────────────
	//
	// 雲端也有一條鏈，但這一份的意義正是**他不必相信我們那一份**：它在他的磁碟
	// 上、離線讀得到、用雜湊串起來，被動過就驗得出來。那是我們對使用者的承諾
	// 之一，而承諾沒有實作就是謊話。
	//
	// 開不起來不是致命的（一台寫不了設定目錄的機器仍然該連得上），但一定要說
	// 出來 —— 安靜地不記錄，就是那個謊話的另一種形式。
	auditLog, auditErr := audit.Open(filepath.Join(config.Dir(), "audit.jsonl"))
	if auditErr != nil {
		fmt.Println("⚠ 稽核檔開不起來，這台機器上的動作不會留下紀錄：", auditErr)
	}
	auditFn := func(op, detail, verdict, actionID string) {
		if auditLog == nil {
			return
		}
		if _, err := auditLog.Append(op, detail, audit.Verdict(verdict), actionID); err != nil {
			fmt.Println("⚠ 稽核寫不進去：", err)
		}
	}

	// ── 互動式終端機 ────────────────────────────────────────────────────
	//
	// Contain 給的是 scope 本身（*runner.Scope 剛好滿足那個窄介面）；不給的話
	// 任何帶 cwd 的開啟請求都會被拒絕，而那個 fail-closed 是刻意的。
	terminals := terminal.New(terminal.Options{
		Root:     root,
		Contain:  scope,
		Approval: host.TerminalGate(gate),
		Audit:    auditFn,
	})

	// ── 本機 MCP ────────────────────────────────────────────────────────
	//
	// 授權檔在啟動時讀一次，改了要重開 —— 一個每次呼叫都重讀的授權檔，等於
	// 任何能寫那個檔案的東西可以在一次對話進行到一半的時候把新的 server 塞進來。
	localMCP := mcp.NewHost(mcp.HostOptions{
		Approvals: host.MCPApprovals(gate),
		Audit:     auditFn,
		// 工具回傳的東西會經過雲端到模型供應商，所以跟指令輸出走同一道遮蔽。
		Redact: func(s string) string { return redact.Redact(s).Text },
		Log:    mcp.Logger(logf),
	})
	for _, e := range localMCP.GrantErrors() {
		fmt.Println("⚠ 本機 MCP 授權檔：", e)
	}

	var client *relay.Client
	var mu sync.Mutex
	send := func(r relay.Result) {
		mu.Lock()
		c := client
		mu.Unlock()
		if c != nil {
			c.Send(r)
		}
	}

	// ── 自動更新 ────────────────────────────────────────────────────────
	//
	// IsBusy 一定要接：不接的話更新會打斷正在跑的指令，或是換掉一個有人正在
	// 裡面打字的終端機。h 在下一行才建好，所以這裡用閉包延後取用。
	var h *host.Host
	up := update.New(update.Deps{
		Server:         cfg.Server,
		CurrentVersion: relay.Version,
		Home:           config.Dir(),
		IsBusy:         func() bool { return h != nil && h.Busy() },
		Quiesce:        func() error { stop(); return nil },
		Log:            logf,
	})

	h = host.New(host.Options{
		Root:        root,
		Scope:       scope,
		MachineID:   cfg.MachineID,
		Gate:        gate,
		Confine:     conf,
		NewCommands: func(e runner.ExecEvents) host.Commands { return runner.New(e) },
		Terminals:   terminals,
		MCP:         localMCP,
		DeviceStore: devices,
		Update:      up,
		Audit:       auditFn,
		Log:         logf,
		// 這台 daemon 真的有出站遮蔽（exec 的輸出、readFile 的內容、MCP 的
		// 回傳都走 internal/redact）。照抄 true 而實際上沒有的話，畫面就會
		// 對使用者說謊 —— 所以這個值是事實，不是常數。
		Redaction: true,
	})
	// 程式結束前把子行程收乾淨：指令、終端機、MCP server。不收的話它們會活過
	// 這個程式，而 relay 已經走了，所以之後沒有人叫得動、也殺得掉它們。
	defer h.Close()

	client = &relay.Client{
		ServerURL: cfg.Server,
		MachineID: cfg.MachineID,
		Ticket:    func(ctx context.Context) (string, error) { return fetchTicket(ctx, cfg) },
		OnState: func(connected bool, detail string) {
			if !connected {
				fmt.Printf("○ 離線 —— %s\n", detail)
				return
			}
			fmt.Printf("● 已連線 %s（%s）\n", cfg.Server, cfg.Label)
			// hello 要在**連上之後**才送得出去（伺服器沒有那條連線就回 409）。
			// 另開一個 goroutine：這個回呼跑在讀 SSE 的那條路上，擋住它等於
			// 擋住所有下行訊息。
			go sayHello(ctx, cfg, h)
		},
		OnRevoke: func(reason string) {
			fmt.Println("這台電腦已經在網頁上被移除了：", reason)
		},
		OnMessage: func(m relay.Down) {
			inv, ok := m.AsInvoke()
			if !ok {
				return
			}
			// relay 已經替每一則下行開了自己的 goroutine，所以這裡可以直接
			// 擋住（exec 與 terminalOpen 都會擋到結束為止）。
			h.Dispatch(inv, send)
		},
	}

	fmt.Printf("連線中… %s（機器 %s）\n", cfg.Server, cfg.MachineID)
	fmt.Println("這台機器提供：", strings.Join(h.Ops(), ", "))
	client.Run(ctx)

	fmt.Println("已停止。")
}

// sayHello 告訴雲端這台機器是什麼、做得到什麼。
//
// 畫面靠它說「這台機器現在是哪一種」：關押是哪一種、憑證目錄擋不擋得住、
// 出站遮蔽開了沒、本機 MCP 有哪幾台、裝置核准註冊了幾把。送的是**事實**，
// 不是我們希望的狀態 —— 要怎麼講給人聽是 UI 的事。
//
// 這裡另外換一張憑證，是因為 relay.Client 沒有把它手上那一張交出來的介面
// （見 doc.go 的「需要補的公開介面」）。多一次往返，但只在每次連上的時候一次。
func sayHello(ctx context.Context, cfg *config.Config, h *host.Host) {
	jwt, err := fetchTicket(ctx, cfg)
	if err != nil {
		fmt.Println("hello 送不出去（拿不到憑證）：", err)
		return
	}
	body, err := json.Marshal(h.Hello())
	if err != nil {
		fmt.Println("hello 組不出來：", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(cfg.Server, "/")+"/api/machines/relay/hello", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+jwt)
	req.Header.Set("user-agent", "rabi-local-go/"+relay.Version)
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		fmt.Println("hello 送不出去：", err)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Printf("hello 被拒絕：HTTP %d\n", res.StatusCode)
	}
}

// fetchTicket 用長期憑證換一張短命的連線憑證。每次重連都重新換一張。
func fetchTicket(ctx context.Context, cfg *config.Config) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.Server+"/api/desktop/relay/ticket", strings.NewReader("{}"))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+cfg.DeviceToken)
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out struct {
		Ticket string `json:"ticket"`
		Error  string `json:"error"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != http.StatusOK || out.Ticket == "" {
		if out.Error != "" {
			return "", fmt.Errorf("%s", out.Error)
		}
		return "", fmt.Errorf("伺服器回 HTTP %d", res.StatusCode)
	}
	return out.Ticket, nil
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		die("%v", err)
	}
}

// runtimeGOOS 包一層是為了讓 osName 可以在測試裡被替換。
func runtimeGOOS() string { return runtime.GOOS }
