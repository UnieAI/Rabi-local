package update

// update.go —— 自己把自己換掉，而且只換得成我們簽過的那一份。
//
// 流程（每一步都可以失敗，而且失敗都要留得下痕跡）：
//
//  1. 抓 manifest（GET <server>/api/machines/ava-local/releases/latest）
//  2. **驗簽章** —— 不是我們的私鑰簽的就到此為止（verify.go）
//  3. 比版本；不比現在新就什麼都不做（**不做降版**，見下）
//  4. **等到閒置** —— 一輪跑到一半的時候不換檔
//  5. 下載 → 比 size + sha256（簽章蓋住 sha256，所以這一步才是真的閘門）
//  6. 讓新的執行檔跑一次 version，它自己報得出版本才算「起得來」
//  7. 舊的改名留著 → 新的搬進原位 → 開一個新的行程 → 確認它真的活著
//  8. 沒活著就**退回舊的**並把舊的重新開起來，而且要說出「這台電腦現在還好好的」
//
// 為什麼不做降版：manifest 是雲端遞過來的，而雲端是我們假設可能被打下來的
// 那一端。簽章擋得住「裝一個我們沒發過的東西」，擋不住「裝一個我們發過、但
// 有已知漏洞的舊版本」。拒絕往回走，那條路就也關上了。
//
// 為什麼 Apply 立刻回：relay 的 invoke 最多等幾十秒，而「等閒置」可能要等幾
// 分鐘到幾十分鐘。所以 Apply 收下就回，真正的工作在背景跑，網頁那邊用
// updateStatus 問進度。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// State 是更新走到哪一步了。字串與 TS 版一致，網頁那邊共用同一組判斷。
type State string

const (
	StateIdle           State = "idle"
	StateChecking       State = "checking"
	StateWaitingForIdle State = "waiting_for_idle"
	StateDownloading    State = "downloading"
	StateVerifying      State = "verifying"
	StateInstalling     State = "installing"
	StateRestarting     State = "restarting"
	StateFailed         State = "failed"
	StateUpToDate       State = "up_to_date"
)

// Outcome 是上一次換版發生了什麼。
//
// 換版成功的那個行程已經不在了，所以這是唯一說得出「剛剛換過版」或者
// 「換過去起不來、已經退回來了」的地方。退回的時候更重要：使用者按了更新、
// 機器版本卻沒變，唯一的解釋在這個檔裡。
type Outcome struct {
	At     string `json:"at"`
	From   string `json:"from"`
	To     string `json:"to"`
	Result string `json:"result"` // installed / rolled_back / failed
	Error  string `json:"error,omitempty"`
}

// Status 是要給網頁看的進度。JSON 欄位與 TS 的 UpdateStatus 一致。
type Status struct {
	State           State    `json:"state"`
	CurrentVersion  string   `json:"currentVersion"`
	TargetVersion   string   `json:"targetVersion"`
	Message         string   `json:"message"`
	Error           string   `json:"error"`
	DownloadedBytes int64    `json:"downloadedBytes"`
	TotalBytes      int64    `json:"totalBytes"`
	LastOutcome     *Outcome `json:"lastOutcome"`
	UpdatedAt       string   `json:"updatedAt"`
}

// CheckResult 是「有沒有新版」的答案。
type CheckResult struct {
	OK             bool   `json:"ok"`
	Available      bool   `json:"available"`
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion,omitempty"`
	Released       string `json:"released,omitempty"`
	// Notes 是**驗過簽章**的更新說明。沒驗過的字不會走到這裡。
	Notes string `json:"notes,omitempty"`
	// Reason 與 Gate 說明沒過的是哪一關（簽章／sha256／版本…）。
	Reason string `json:"reason,omitempty"`
	Gate   Gate   `json:"gate,omitempty"`
}

const (
	defaultIdlePoll     = 2 * time.Second
	defaultIdleWaitMax  = 30 * time.Minute
	defaultHandoverWait = 12 * time.Second
	smokeTestTimeout    = 20 * time.Second
	handoverPoll        = 500 * time.Millisecond
	stateFileName       = "update-state.json"
)

// Deps 是 Updater 要向外界借的東西。只有 Server／CurrentVersion／Home 是必填，
// 其餘都有預設值；測試靠換掉它們把整條路徑跑完。
type Deps struct {
	// Server 是這台電腦連的那個 copilot-v2（config.Config.Server）。
	Server string
	// CurrentVersion 是現在跑的版本（relay.Version）。
	CurrentVersion string
	// Home 是設定檔所在的資料夾（config.Dir()）；暫存與狀態檔都放這裡。
	Home string

	// ExecPath 是正在跑的執行檔，預設 os.Executable()。
	ExecPath string
	// GOOS/GOARCH 決定要拿哪一個檔，預設 runtime.GOOS/GOARCH。
	GOOS, GOARCH string

	// IsBusy 回答「手邊還有事在做嗎」。main.go 接 runner.Running() > 0。
	// 沒接的話預設「永遠不忙」—— 那會讓更新打斷正在跑的指令，所以要接。
	IsBusy func() bool
	// Quiesce 在換檔之前把自己安靜下來（停 relay、放掉該放的東西）。
	Quiesce func() error
	// HandoverOK 確認新的行程真的接手了（不只是「還活著」）。
	HandoverOK func(pid int) bool

	// RestartArgs 是重新啟動時要帶的參數。Go 版沒有子命令時留空即可。
	RestartArgs []string
	// VersionArgs 是冒煙測試的參數，預設 ["version"]；新的執行檔要在 stdout
	// 印出**乾淨的版本號**（例如 0.2.0）並以 0 結束，否則這次更新不會發生。
	VersionArgs []string

	HTTP         *http.Client
	PublicKeyPEM string
	Exit         func(code int)
	Now          func() time.Time
	Log          func(format string, a ...any)
	OnStatus     func(Status)

	IdlePoll     time.Duration
	IdleWaitMax  time.Duration
	HandoverWait time.Duration

	// AllowSelfReplace：這個行程換得掉自己嗎。
	//
	// nil＝自己判斷，而且**預設是不行的那一邊**：用 `go run` 跑的時候執行檔
	// 是編譯出來的暫存檔，換它沒有意義（下次 go run 又是新的一個），更糟的是
	// 會在開發者機器的暫存目錄留下一個會自己上線的 daemon。
	AllowSelfReplace *bool
}

// Updater 是自動更新的對外把手。用 New 建，由 main.go 保管一份。
type Updater struct {
	d Deps

	mu      sync.Mutex
	status  Status
	running bool
}

// New 建一個 Updater。缺的欄位在這裡補上預設值，之後不再回頭看 Deps 的零值。
func New(d Deps) *Updater {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
	}
	if d.HTTP == nil {
		// 下載一個上百 MB 的執行檔可能很久，但也不能永遠掛著。
		d.HTTP = &http.Client{Timeout: 30 * time.Minute}
	}
	if d.PublicKeyPEM == "" {
		d.PublicKeyPEM = PublicKeyPEM
	}
	if d.GOOS == "" {
		d.GOOS = runtime.GOOS
	}
	if d.GOARCH == "" {
		d.GOARCH = runtime.GOARCH
	}
	if d.ExecPath == "" {
		if p, err := os.Executable(); err == nil {
			d.ExecPath = p
		}
	}
	if d.IsBusy == nil {
		d.IsBusy = func() bool { return false }
	}
	if d.Exit == nil {
		d.Exit = os.Exit
	}
	if len(d.VersionArgs) == 0 {
		d.VersionArgs = []string{"version"}
	}
	if d.IdlePoll <= 0 {
		d.IdlePoll = defaultIdlePoll
	}
	if d.IdleWaitMax <= 0 {
		d.IdleWaitMax = defaultIdleWaitMax
	}
	if d.HandoverWait <= 0 {
		d.HandoverWait = defaultHandoverWait
	}
	u := &Updater{d: d}
	u.status = Status{
		State:          StateIdle,
		CurrentVersion: d.CurrentVersion,
		Message:        "沒有正在進行的更新",
		LastOutcome:    ReadOutcome(d.Home),
		UpdatedAt:      d.Now().UTC().Format(time.RFC3339),
	}
	return u
}

/* ── 狀態 ─────────────────────────────────────────────────────────────── */

// Status 回傳目前的進度（可以在任何 goroutine 呼叫）。
func (u *Updater) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

func (u *Updater) set(mutate func(s *Status)) Status {
	u.mu.Lock()
	mutate(&u.status)
	u.status.UpdatedAt = u.d.Now().UTC().Format(time.RFC3339)
	s := u.status
	u.mu.Unlock()
	if u.d.OnStatus != nil {
		u.d.OnStatus(s)
	}
	return s
}

func (u *Updater) fail(reason string) Status {
	u.d.Log("[update] 更新失敗：%s", reason)
	return u.set(func(s *Status) {
		s.State = StateFailed
		s.Error = reason
		s.Message = "更新沒有完成：" + reason
	})
}

// ReadOutcome 讀「上一次換版發生了什麼」。換版成功的那個行程已經不在了，
// 所以開機之後只有這個檔說得出剛剛發生過什麼（給 doctor／狀態頁用）。
func ReadOutcome(home string) *Outcome {
	raw, err := os.ReadFile(filepath.Join(home, stateFileName))
	if err != nil {
		return nil
	}
	var wrapper struct {
		LastOutcome *Outcome `json:"lastOutcome"`
	}
	if json.Unmarshal(raw, &wrapper) != nil {
		return nil
	}
	return wrapper.LastOutcome
}

func (u *Updater) recordOutcome(o Outcome) {
	u.mu.Lock()
	u.status.LastOutcome = &o
	u.mu.Unlock()
	raw, _ := json.MarshalIndent(map[string]any{"lastOutcome": o}, "", "  ")
	if err := os.MkdirAll(u.d.Home, 0o700); err != nil {
		u.d.Log("[update] 寫不進 %s：%v", stateFileName, err)
		return
	}
	if err := os.WriteFile(filepath.Join(u.d.Home, stateFileName), raw, 0o600); err != nil {
		u.d.Log("[update] 寫不進 %s：%v", stateFileName, err)
	}
}

/* ── 1–3：manifest、簽章、版本 ────────────────────────────────────────── */

// FetchManifest 抓一份 manifest 並驗簽章。驗不過的那一份不會回傳出去。
func (u *Updater) FetchManifest(ctx context.Context) (*Manifest, error) {
	url := strings.TrimRight(u.d.Server, "/") + "/api/machines/ava-local/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "text/plain")
	req.Header.Set("user-agent", "unieai-copilot-desktop/"+u.d.CurrentVersion)
	res, err := u.d.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("連不上 %s：%w", u.d.Server, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拿不到更新資訊（HTTP %d）", res.StatusCode)
	}
	// manifest 是一串短短的 token；讀進來的量要有上限，否則一個「無限長」的
	// 回應在驗簽章之前就能把記憶體吃光。
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("拿不到更新資訊：%w", err)
	}
	text := strings.TrimSpace(string(body))
	// 伺服器可以回純 token，也可以回 { manifest }：外部物件儲存放 JSON 比較常見。
	if strings.HasPrefix(text, "{") {
		var j struct {
			Manifest string `json:"manifest"`
		}
		if json.Unmarshal([]byte(text), &j) == nil && j.Manifest != "" {
			text = strings.TrimSpace(j.Manifest)
		}
	}
	if text == "" {
		return nil, errors.New("這個站台還沒有發布過更新檔")
	}
	return VerifyManifest(text, u.d.PublicKeyPEM)
}

// Check 問「有沒有新版」。不會動到磁碟上的任何東西。
func (u *Updater) Check(ctx context.Context) CheckResult {
	m, err := u.FetchManifest(ctx)
	if err != nil {
		return CheckResult{CurrentVersion: u.d.CurrentVersion, Reason: err.Error(), Gate: GateOf(err)}
	}
	key := ArtifactKey(u.d.GOOS, u.d.GOARCH)
	if _, ok := m.Artifacts[key]; !ok {
		return CheckResult{
			CurrentVersion: u.d.CurrentVersion,
			LatestVersion:  m.Version,
			Reason:         fmt.Sprintf("這個版本沒有 %s 的檔案", key),
			Gate:           GatePlatform,
		}
	}
	return CheckResult{
		OK:             true,
		Available:      IsNewerVersion(m.Version, u.d.CurrentVersion),
		CurrentVersion: u.d.CurrentVersion,
		LatestVersion:  m.Version,
		Released:       m.Released,
		Notes:          m.Notes,
	}
}

/* ── 4：等閒置 ────────────────────────────────────────────────────────── */

// waitForIdle 等到手邊沒事。換檔會殺掉現在這個行程 —— 手邊有一條 exec 或一個
// 開著的終端機的時候換，使用者看到的是「做到一半忽然斷了」，而且他永遠不會
// 知道為什麼。
func (u *Updater) waitForIdle(ctx context.Context) bool {
	deadline := u.d.Now().Add(u.d.IdleWaitMax)
	for u.d.IsBusy() {
		if u.d.Now().After(deadline) {
			return false
		}
		u.set(func(s *Status) {
			s.State = StateWaitingForIdle
			s.Message = "有新版，等這台電腦手邊的事做完再換"
		})
		select {
		case <-ctx.Done():
			return false
		case <-time.After(u.d.IdlePoll):
		}
	}
	return true
}

/* ── 5–6：下載、驗章、試跑 ───────────────────────────────────────────── */

func (u *Updater) download(ctx context.Context, m *Manifest) (string, error) {
	key := ArtifactKey(u.d.GOOS, u.d.GOARCH)
	a, ok := m.Artifacts[key]
	if !ok {
		return "", gateErr(GatePlatform, "這個版本沒有 %s 的檔案", key)
	}
	u.set(func(s *Status) {
		s.State = StateDownloading
		s.TargetVersion = m.Version
		s.TotalBytes = a.Size
		s.DownloadedBytes = 0
		s.Message = "下載 " + m.Version
	})

	url := fmt.Sprintf("%s/api/machines/ava-local/releases/%s/%s",
		strings.TrimRight(u.d.Server, "/"), pathEscape(m.Version), pathEscape(a.File))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("user-agent", "unieai-copilot-desktop/"+u.d.CurrentVersion)
	res, err := u.d.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("下載失敗：%w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下載失敗（HTTP %d）", res.StatusCode)
	}

	// 多讀一個 byte 就知道對方是不是給了比 manifest 說的還多 —— 一個「無限長」
	// 的回應可以在驗 sha256 之前先把記憶體吃光。
	data := make([]byte, 0, a.Size)
	buf := make([]byte, 64*1024)
	reader := io.LimitReader(res.Body, a.Size+1)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if int64(len(data)) > a.Size {
				return "", errors.New("下載的內容比 manifest 說的還大")
			}
			u.set(func(s *Status) { s.DownloadedBytes = int64(len(data)) })
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("下載失敗：%w", err)
		}
	}

	u.set(func(s *Status) {
		s.State = StateVerifying
		s.Message = "核對這份檔案是不是我們簽的那一份"
	})
	if err := VerifyBytes(data, a); err != nil {
		return "", err
	}

	dir := filepath.Join(u.d.Home, "updates", m.Version)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("寫不進暫存檔：%w", err)
	}
	staged := filepath.Join(dir, a.File)
	if err := os.WriteFile(staged, data, 0o755); err != nil {
		return "", fmt.Errorf("寫不進暫存檔：%w", err)
	}
	_ = os.Chmod(staged, 0o755)
	return staged, nil
}

// smokeTest 問新的執行檔「你是哪一版」。
//
// 「起不來要能退回去」的第一道防線，而且是最便宜的一道。少了這一步，一個缺了
// 相依、或平台抓錯的檔案會在**換過去之後**才被發現 —— 那時候使用者的電腦上
// 已經沒有一個能跑的程式了。
func (u *Updater) smokeTest(ctx context.Context, file, expectVersion string) error {
	ctx, cancel := context.WithTimeout(ctx, smokeTestTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, file, u.d.VersionArgs...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("新的執行檔回了 exit %d", ee.ExitCode())
		}
		return fmt.Errorf("新的執行檔跑不起來：%w", err)
	}
	said := strings.TrimSpace(string(out))
	if said != expectVersion {
		if len(said) > 40 {
			said = said[:40]
		}
		return fmt.Errorf("新的執行檔說它是「%s」，manifest 說 %s", said, expectVersion)
	}
	return nil
}

/* ── 7–8：換檔、接手、退回 ───────────────────────────────────────────── */

func (u *Updater) backupPath() string {
	return u.d.ExecPath + ".old-" + u.d.CurrentVersion
}

// swapIn 把新的搬進原位，回傳舊的被放到哪裡。
func (u *Updater) swapIn(staged string) (string, error) {
	backup := u.backupPath()
	_ = os.Remove(backup)
	// 先改名再複製，而不是直接覆寫：
	//   · Windows 不讓你覆寫正在跑的執行檔，但**讓你改它的名字**，這是那個
	//     平台上唯一能原地換版的做法；
	//   · 任何平台上，改名都是原子的，所以中途斷電不會留下半個檔案。
	if err := os.Rename(u.d.ExecPath, backup); err != nil {
		return "", fmt.Errorf("換檔失敗：%w", err)
	}
	if err := copyFile(staged, u.d.ExecPath); err != nil {
		// 複製失敗＝原位現在是空的。立刻把舊的搬回來，這台電腦不能沒有
		// 可以跑的執行檔。
		if back := os.Rename(backup, u.d.ExecPath); back != nil {
			return "", fmt.Errorf("換檔失敗：%v，而且舊的也搬不回去（它在 %s，手動搬回原位即可）", err, backup)
		}
		return "", fmt.Errorf("換檔失敗：%w（舊的已經放回原位，這台電腦還是好好的）", err)
	}
	return backup, nil
}

// handover 把新的那一個叫起來，並確認它真的接手了。
func (u *Updater) handover(ctx context.Context) error {
	u.set(func(s *Status) {
		s.State = StateRestarting
		s.Message = "換好了，正在把新的那一個叫起來"
	})
	sp, err := u.spawnDaemon()
	if err != nil {
		return fmt.Errorf("新的行程開不起來：%w", err)
	}
	deadline := u.d.Now().Add(u.d.HandoverWait)
	for u.d.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sp.done:
			return errors.New("新的行程起來之後馬上就結束了")
		case <-time.After(handoverPoll):
		}
		// 「還活著」不等於「接手了」：接手的判準由 main.go 給（例如 relay
		// 重新連上），沒給就只看它有沒有活過這段時間。
		if u.d.HandoverOK == nil || u.d.HandoverOK(sp.pid) {
			return nil
		}
	}
	select {
	case <-sp.done:
		return errors.New("新的行程沒有活過接手")
	default:
		return errors.New("新的行程起來了，但一直沒有接手")
	}
}

// spawned 是剛開起來的那個行程。done 在它結束時關閉。
type spawned struct {
	pid  int
	done chan struct{}
}

// spawnDaemon 開一個新的自己（脫離這個行程，這個行程馬上就要結束了）。
func (u *Updater) spawnDaemon() (*spawned, error) {
	cmd := exec.Command(u.d.ExecPath, u.d.RestartArgs...)
	cmd.SysProcAttr = detachAttrs()
	if err := os.MkdirAll(u.d.Home, 0o700); err == nil {
		if f, err := os.OpenFile(filepath.Join(u.d.Home, "daemon.log"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			defer f.Close() // 子行程已經拿到自己的 fd，這一份可以放掉
			cmd.Stdout, cmd.Stderr = f, f
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	sp := &spawned{pid: cmd.Process.Pid, done: make(chan struct{})}
	// **一定要收屍。** 不 Wait 的話，unix 上那個行程結束後會變成 zombie，
	// 而 zombie 對「那個 pid 還在嗎」的每一種問法都回答「還在」—— 一個換過去
	// 就死的版本會被誤判成接手成功，回滾那條路就永遠不會走到。
	// （這不是假想：第一版就是這樣寫的，回滾測試當場抓到。）
	go func() {
		_ = cmd.Wait()
		close(sp.done)
	}()
	return sp, nil
}

// rollback 退回舊版，並把舊的重新開起來。
//
// 這裡最重要的一句話不是「失敗了」，是**「那台電腦現在還好好的」** ——
// 使用者按了更新、版本卻沒變，他要知道的是自己的電腦沒事，而不是一串錯誤。
func (u *Updater) rollback(backup, reason string) {
	u.d.Log("[update] 退回舊版（%s）：%s", u.d.CurrentVersion, reason)
	target := u.Status().TargetVersion
	if target == "" {
		target = "?"
	}
	at := u.d.Now().UTC().Format(time.RFC3339)

	_ = os.Remove(u.d.ExecPath)
	if err := copyFile(backup, u.d.ExecPath); err != nil {
		u.recordOutcome(Outcome{At: at, From: u.d.CurrentVersion, To: target, Result: "failed",
			Error: fmt.Sprintf("退回失敗：%v（舊的執行檔在 %s）", err, backup)})
		u.fail(fmt.Sprintf("退回也失敗了：%v。舊的執行檔還在 %s，手動搬回去即可。", err, backup))
		return
	}
	u.recordOutcome(Outcome{At: at, From: u.d.CurrentVersion, To: target, Result: "rolled_back", Error: reason})
	u.fail(fmt.Sprintf("更新沒有成功，已經退回 %s —— **這台電腦現在還是好好的**，原本的功能都在。原因：%s",
		u.d.CurrentVersion, reason))

	// 舊的已經放回原位了，但現在這個行程已經把自己安靜下來（Quiesce）。
	// 再把舊的開起來，使用者的電腦才會重新上線。
	if _, err := u.spawnDaemon(); err != nil {
		u.d.Log("[update] 舊版重開失敗：%v（重新開機或手動啟動即可）", err)
		return
	}
	u.d.Exit(1)
}

/* ── 對外 ─────────────────────────────────────────────────────────────── */

// PerformUpdate 跑完整條路（等閒置 → 下載 → 驗 → 換 → 接手／退回）。
//
// 成功的話這個行程會結束（Exit(0)），因為新的那一個已經接手了。
// CLI 想同步等它跑完就直接呼叫這支；Apply 則是把它丟到背景。
func (u *Updater) PerformUpdate(ctx context.Context, m *Manifest) {
	defer func() {
		u.mu.Lock()
		u.running = false
		u.mu.Unlock()
	}()

	if !u.selfReplaceAllowed() {
		u.fail(notUpdatableMessage)
		return
	}
	if !u.waitForIdle(ctx) {
		u.fail("這台電腦一直在忙（有指令還在跑），這次先不換。手邊的事做完再按一次更新。")
		return
	}
	staged, err := u.download(ctx, m)
	if err != nil {
		u.fail(err.Error())
		return
	}

	u.set(func(s *Status) {
		s.State = StateInstalling
		s.Message = "檢查新的執行檔跑不跑得起來"
	})
	if err := u.smokeTest(ctx, staged, m.Version); err != nil {
		u.fail(err.Error())
		return
	}

	if u.d.Quiesce != nil {
		if err := u.d.Quiesce(); err != nil {
			u.d.Log("[update] 安靜下來的時候出了點事：%v", err)
		}
	}

	backup, err := u.swapIn(staged)
	if err != nil {
		u.fail(err.Error())
		return
	}
	if err := u.handover(ctx); err != nil {
		u.rollback(backup, err.Error())
		return
	}

	u.recordOutcome(Outcome{At: u.d.Now().UTC().Format(time.RFC3339),
		From: u.d.CurrentVersion, To: m.Version, Result: "installed"})
	u.d.Log("[update] 已更新到 %s，舊的執行檔留在 %s", m.Version, backup)
	// 暫存的那一份已經搬到原位了，留著只是佔空間。
	_ = os.RemoveAll(filepath.Join(u.d.Home, "updates", m.Version))
	u.d.Exit(0)
}

// OpResult 是雲端那三個 op 的回覆形狀（relay 的 result frame）。
type OpResult struct {
	OK     bool           `json:"ok"`
	Output map[string]any `json:"output"`
}

func opError(code, message string) OpResult {
	return OpResult{OK: false, Output: map[string]any{
		"error": map[string]any{"code": code, "message": message},
	}}
}

const notUpdatableMessage = "這個執行檔換不掉自己（多半是用 go run 跑的）。用打包出來的執行檔才會自動更新。"

// Apply 是「按下更新」。
//
// **立刻回**：等閒置可能要等很久，而 relay 的 invoke 等不了那麼久。收下之後
// 真正的工作在背景跑，網頁那邊用 updateStatus 問進度。
//
// wantVersion 可以指定要裝哪一版，但只接受「跟 daemon 自己抓到的最新版一致」——
// 這個欄位存在只是為了讓 UI 說得出它按的是什麼，不是讓呼叫端挑版本。
func (u *Updater) Apply(ctx context.Context, wantVersion string) OpResult {
	if os.Getenv("AVA_LOCAL_UPDATE_DISABLED") == "1" {
		return opError("update_disabled", "這台機器關掉了自動更新（AVA_LOCAL_UPDATE_DISABLED=1）。")
	}
	u.mu.Lock()
	already := u.running
	u.mu.Unlock()
	if already {
		return OpResult{OK: true, Output: map[string]any{"accepted": true, "alreadyRunning": true, "status": u.Status()}}
	}
	if !u.selfReplaceAllowed() {
		return opError("not_updatable", notUpdatableMessage)
	}

	u.set(func(s *Status) {
		s.State = StateChecking
		s.Error = ""
		s.Message = "看看有沒有新版"
	})
	m, err := u.FetchManifest(ctx)
	if err != nil {
		return opError("update_unavailable", u.fail(err.Error()).Message)
	}

	if !IsNewerVersion(m.Version, u.d.CurrentVersion) {
		// **不做降版。** 簽章擋得住「裝一個我們沒發過的東西」，擋不住「裝一個
		// 我們發過、但有已知漏洞的舊版本」。
		u.set(func(s *Status) {
			s.State = StateUpToDate
			s.TargetVersion = m.Version
			s.Message = fmt.Sprintf("已經是最新的（%s）", u.d.CurrentVersion)
		})
		return OpResult{OK: true, Output: map[string]any{"accepted": false, "upToDate": true, "status": u.Status()}}
	}
	if wantVersion != "" && wantVersion != m.Version {
		return opError("version_mismatch", fmt.Sprintf("現在最新的是 %s，不是 %s", m.Version, wantVersion))
	}
	if m.MinVersion != "" && IsNewerVersion(m.MinVersion, u.d.CurrentVersion) {
		why := fmt.Sprintf("這個版本要從 %s 以上才換得過去，這台是 %s，請重新下載安裝一次。",
			m.MinVersion, u.d.CurrentVersion)
		return opError("manual_reinstall_required", u.fail(why).Message)
	}
	if _, ok := m.Artifacts[ArtifactKey(u.d.GOOS, u.d.GOARCH)]; !ok {
		why := fmt.Sprintf("這個版本沒有 %s 的檔案", ArtifactKey(u.d.GOOS, u.d.GOARCH))
		return opError("no_artifact", u.fail(why).Message)
	}

	u.mu.Lock()
	u.running = true
	u.mu.Unlock()
	busy := u.d.IsBusy()
	u.set(func(s *Status) {
		s.TargetVersion = m.Version
		if busy {
			s.State, s.Message = StateWaitingForIdle, "有新版，等這台電腦手邊的事做完再換"
		} else {
			s.State, s.Message = StateDownloading, "準備更新到 "+m.Version
		}
	})
	// 背景跑：context 不能綁在這個請求上，不然 relay 一回應就被取消。
	go u.PerformUpdate(context.WithoutCancel(ctx), m)

	return OpResult{OK: true, Output: map[string]any{
		"accepted": true, "targetVersion": m.Version, "notes": m.Notes, "status": u.Status(),
	}}
}

// Ops 是雲端能對「更新」下的三個命令，給 main.go 接進 relay 的 switch：
//
//	updateCheck  / updateStatus / updateApply
//
// 它們刻意跟檔案／指令那一組分開：不碰授權資料夾、不需要核准票，而且其中
// 一個會把這個行程換掉。
//
// main.go 這樣接（args 就是下行訊息帶的參數，沒有就傳 nil）：
//
//	if out, handled := up.HandleOp(ctx, m.Op, args); handled {
//	        send(result(m.ID, out))
//	}
func (u *Updater) HandleOp(ctx context.Context, op string, args map[string]any) (OpResult, bool) {
	switch op {
	case "updateCheck":
		r := u.Check(ctx)
		return OpResult{OK: true, Output: map[string]any{
			"ok": r.OK, "available": r.Available, "currentVersion": r.CurrentVersion,
			"latestVersion": r.LatestVersion, "released": r.Released, "notes": r.Notes,
			"reason": r.Reason, "gate": string(r.Gate),
		}}, true
	case "updateStatus":
		return OpResult{OK: true, Output: statusOutput(u.Status())}, true
	case "updateApply":
		version, _ := args["version"].(string)
		return u.Apply(ctx, version), true
	}
	return OpResult{}, false
}

// statusOutput 把 Status 轉成 map，欄位名與 TS 版一致（網頁共用同一個畫面）。
func statusOutput(s Status) map[string]any {
	raw, _ := json.Marshal(s)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

/* ── 小工具 ───────────────────────────────────────────────────────────── */

func (u *Updater) selfReplaceAllowed() bool {
	if u.d.AllowSelfReplace != nil {
		return *u.d.AllowSelfReplace
	}
	return !looksLikeGoRun(u.d.ExecPath)
}

// looksLikeGoRun 認出「這個執行檔是 go run 現編出來的暫存檔」。
// 換掉它沒有意義（下次 go run 又是新的一個），而且會在開發者的暫存目錄
// 留下一個會自己上線的 daemon。
func looksLikeGoRun(execPath string) bool {
	if execPath == "" {
		return true
	}
	clean := filepath.ToSlash(execPath)
	if strings.Contains(clean, "/go-build") {
		return true
	}
	tmp := filepath.ToSlash(strings.TrimRight(os.TempDir(), string(os.PathSeparator)))
	return tmp != "" && strings.HasPrefix(clean, tmp+"/")
}

// copyFile 複製並保留可執行權限。**不是 rename** —— 暫存檔與執行檔可能在
// 不同的檔案系統上（Linux 的 /home 與 /tmp 就常常是），rename 會直接失敗。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, 0o755)
}

// pathEscape 讓版本與檔名進網址之前先過一次。兩者在 manifest 那一關就被
// 限制成保守的字元集了，這裡是第二道。
func pathEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, "%%%02X", r)
		}
	}
	return b.String()
}
