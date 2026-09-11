// Package confine 用**作業系統本來就有的東西**把 agent 的指令關住。
//
// # 這一層買到什麼
//
// runner/scope.go 那一道（路徑圍籬）擋得住**檔案工具**：雲端說要讀 ~/.ssh，
// 授權範圍會拒絕。但 `exec` 送下來的是一整串 shell 指令，那串東西一旦跑起來
// 就是使用者本人的權限 —— scope 完全擋不到它。也就是說，在這一層接上以前，
// 「授權資料夾」對 bash 而言只是一個**起始工作目錄**，不是邊界。
//
// 所以這個套件做的是：把 argv 包進作業系統的關押裡，讓「寫只能落在授權資料夾
// 內」這件事由核心執行，而不是由我們的良好意圖執行。
//
//	Linux    bwrap（bubblewrap）    常見（flatpak 會帶），沒有就誠實說沒有
//	macOS    sandbox-exec          系統內建，每一台都有
//	Windows  沒有對等的東西        明著回報不支援，不要假裝（見 native_windows.go）
//
// 條件是**不准要求使用者安裝任何東西**：叫人先裝 Docker Desktop 跟「輕鬆連上」
// 是衝突的，而那個要求擋在最前面的結果，是絕大多數人最後跑的是 Noop()，
// 也就是完全沒有關押。容器那一層（container.go）留著給願意裝的人。
//
// # 關的是「寫」，不是「讀」
//
// 這是整個套件最重要的取捨，寫在這裡免得之後有人以為是漏做。
//
// 把讀也關起來，第一個壞掉的是 agent 自己：node、python、git、編譯器、系統
// 函式庫全都在授權資料夾外面。真的把讀關掉，「幫我跑測試」第一步就失敗，
// 而使用者看到的是一個壞掉的產品，不是一個安全的產品。
//
// 例外是憑證目錄（~/.ssh、~/.aws、鑰匙圈這些）：agent 沒有任何正當理由要讀，
// 而它們正是一旦外洩就最貴的東西。那幾個連讀都擋。
//
// # 已知的缺口：授權資料夾擋得住檔案工具，bash 完全不擋
//
// scope 只管 fs 工具與 exec 的 cwd。指令字串裡寫什麼路徑，scope 看不到也不問。
// 這一層把「寫」關住之後，越界的**寫**會失敗；但越界的**讀**仍然是可以的
// （憑證目錄除外），而且沒有人會被問。TS 版（runtime/apps/ava-local）一樣是
// 這個狀態 —— 這裡不假裝解決了它。真正要補的是 exec 的指令政策（哪些動詞、
// 哪些路徑要人核准），那是另一層，不在這個套件裡。
//
// # 這裡**沒有**做的：子行程的環境變數
//
// 關押之外還有一條路會把祕密交出去：子行程預設繼承 daemon 的整份環境
// （連線憑證、伺服器位址都在裡面）。那一份允許清單已經有人移植好了，在
// internal/mcp/env.go 的 ChildEnv —— 這裡不再抄一份，兩份允許清單會走鐘，
// 而走鐘的那一次沒有任何症狀。
//
// 注意 internal/runner/exec.go 現在給子行程的是 os.Environ() 的**全部**，
// 也就是說這條路目前是開的。接線的人要把 ChildEnv 提到一個共用的地方
// （internal/mcp 不是 exec 該相依的東西），然後兩邊都用它。
//
// # 怎麼接上（main.go 的進入點）
//
//	c, notice := confine.Choose(confine.Preference{Mode: cfg.Sandbox})
//	fmt.Println(notice.Message)            // 照實講這台機器實際上是哪一種
//
//	// 每一條指令：
//	if c.When() == confine.ModeAlways || req.Sandbox {
//	    cmd, err := c.Wrap(argv, confine.Options{Root: root, Cwd: cwd})
//	    if err != nil { /* 回報失敗，**不要**改成不關押就跑 */ }
//	    bin, args := cmd.Split()           // 丟給 exec.Command，Dir 用 cmd.Dir
//	}
//
//	// hello：
//	hello.Posture = confine.PostureOf(c, root, false /* 還沒有出站遮蔽 */)
//
// 那個 `c.When() == ModeAlways || req.Sandbox` 是 TS 版 tool-host.ts 的規則：
// 原生那層不等 agent 開口（不開的話幾乎每條指令都沒有關押），容器那層等
// （起容器要時間，而且容器裡不一定有使用者專案要的 toolchain）。
//
// Wrap 失敗時**不可以**退回沒有關押的 argv：使用者是照 posture 決定要不要把
// 敏感資料放進那個資料夾的，安靜地失去圍籬正是最糟的那一種結果。
package confine

// Mode 說的是「這層關押什麼時候生效」。
//
// 兩種關押的代價差很多，所以預設也不一樣：
//
//	容器（ModeOnRequest）—— 起一個容器要時間，而且容器裡不一定有使用者專案
//	  需要的 toolchain。預設全開會讓「幫我跑測試」莫名其妙地失敗。
//	原生（ModeAlways）—— 同一批二進位檔，只是多一道寫入圍籬，幾乎不花成本。
//	  這種**不開才奇怪**：不開的話絕大多數指令是完全沒有關押的。
type Mode string

const (
	// ModeAlways 每一條指令都關，不等 agent 開口。
	ModeAlways Mode = "always"
	// ModeOnRequest 只有 agent 主動要求（sandbox: true）才關。
	ModeOnRequest Mode = "on-request"
)

// Options 是包一條指令需要知道的兩件事。
//
// Cwd 要一起傳，是因為會搬動檔案系統的關押（容器）必須連工作目錄一起搬 ——
// 容器裡看到的授權資料夾跟主機上的路徑不一樣。
type Options struct {
	// Root 是使用者授權的資料夾。寫入只能落在這裡面。
	Root string
	// Cwd 是指令要從哪裡開始跑。必須已經通過 scope 檢查。
	Cwd string
}

// Command 是包好之後真正要執行的東西。
type Command struct {
	// Argv[0] 是要執行的程式，其餘是參數。
	Argv []string
	// Dir 是**主機上**的工作目錄。容器那一層會把它改成掛載點的主機路徑，
	// 因為主機端的 cwd 就算沒有意義也必須存在，否則連 spawn 都會失敗。
	Dir string
}

// Split 把 Command 拆成 exec.Command 要的形狀。
func (c Command) Split() (string, []string) {
	if len(c.Argv) == 0 {
		return "", nil
	}
	return c.Argv[0], c.Argv[1:]
}

// Confinement 是一種關押方式。
type Confinement interface {
	// Name 是這種關押的名字，"none" 代表沒有。會出現在 posture 裡，
	// 所以它必須說實話 —— 使用者是照這個字決定要不要把敏感資料放進去的。
	Name() string
	// When 見 Mode。
	When() Mode
	// Wrap 把 argv 改寫成「由作業系統執行授權範圍」的版本。
	//
	// 做不到就回 error，**不會**偷偷退回沒有關押的版本：那正是
	// 「以為有保護，其實沒有」的來源。
	Wrap(argv []string, opts Options) (Command, error)
}

// noop 是沒有關押。它存在是為了讓呼叫端不必到處判斷 nil，
// 但它的名字一定是 "none"，posture 也就會照實說這台機器沒有關押。
type noop struct{}

func (noop) Name() string { return "none" }
func (noop) When() Mode   { return ModeOnRequest }
func (noop) Wrap(argv []string, opts Options) (Command, error) {
	return Command{Argv: argv, Dir: opts.Cwd}, nil
}

// Noop 回傳「沒有關押」。指令會直接在使用者的電腦上跑。
func Noop() Confinement { return noop{} }

// Posture 是這台機器**實際上**是什麼狀態，送在 hello 裡給網頁打勾用。
//
// 欄位名對齊 TS 版的 DaemonPosture（lib/machines/posture-checks.ts 是雲端那一側
// 怎麼翻譯它），這樣同一個畫面不必分兩種 daemon 寫兩套。
//
// 一個相信自己被關押、實際上沒有的人，處境比知道自己沒有的人更糟：他會把
// 敏感資料放進那個資料夾。所以這裡送的是**事實**，不是我們希望的狀態；
// 要怎麼講給人聽是 UI 的事，不是這裡的事。
type Posture struct {
	// Confinement 關押方式的名字；"none" 代表沒有。
	Confinement string `json:"confinement"`
	// ConfinementWhen "always" ＝ 每一條指令都關；"on-request" ＝ 只有 agent 開口才關。
	ConfinementWhen Mode `json:"confinementWhen"`
	// GrantedRoot 授權資料夾。有關押時，寫入只能落在這裡面。
	GrantedRoot string `json:"grantedRoot"`
	// OutboundRedaction 祕密在離開這台電腦前會不會被蓋掉。
	//
	// **Go 版目前沒有這一層**（TS 版有 redact.ts）。接線的人如果照抄 true，
	// 畫面就會對使用者說謊，所以這個值是參數而不是常數。
	OutboundRedaction bool `json:"outboundRedaction"`
	// SecretsHidden 憑證目錄是不是連讀都擋。
	SecretsHidden bool `json:"secretsHidden"`
}

// PostureOf 把一個 Confinement 翻成要送上去的事實。
//
// redaction 傳的是「這台 daemon 現在有沒有出站遮蔽」，見 Posture.OutboundRedaction。
func PostureOf(c Confinement, root string, redaction bool) Posture {
	if c == nil {
		c = Noop()
	}
	return Posture{
		Confinement:     c.Name(),
		ConfinementWhen: c.When(),
		GrantedRoot:     root,
		// 憑證目錄只有原生那一層擋得住，而且只有在它**預設就開**的時候才算數：
		// 等 agent 開口才關的關押，絕大多數指令是沒有經過它的。
		SecretsHidden:     c.Name() != "none" && c.When() == ModeAlways,
		OutboundRedaction: redaction,
	}
}
