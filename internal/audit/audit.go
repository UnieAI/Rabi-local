// Package audit 是**這台機器自己那一份紀錄**：在它上面跑過什麼。
//
// 對應 runtime/apps/ava-local/src/audit.ts，格式逐位元組相同。
//
// ## 為什麼機器上要留一份
//
// 雲端也有一條鏈（`user_machine_audit`）。這一份的意義不是備份，是
// **使用者不必相信我們那一份** —— 它在他自己的磁碟上，離線讀得到，而且用
// 雜湊串起來：抽掉中間一列、或改掉任何一個欄位，`Verify` 就指得出是第幾列。
//
// 那句話是我們對使用者的承諾之一（見 lib/machines/posture-checks.ts 的
// 「做過什麼在你自己的電腦上留了一份」）。**承諾沒有實作就是謊話**，所以這個
// 套件不是加分項。
//
// ## 只 append，而且不吞錯
//
// 寫不進去要讓呼叫端知道。ADR-0002 那條規則（寫不進稽核就不發票）在 app 那側
// 成立，在這裡也一樣：一個「做了但沒留下紀錄」的動作，比一個沒做成的動作糟。
package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/UnieAI/Rabi-local/internal/canonical"
)

// Verdict 是這一次動作的下場。字串跟 TS 版逐字相同 —— 兩邊的紀錄要放得進
// 同一個分析。
type Verdict string

const (
	Run     Verdict = "run"     // 人批准了，跑了
	Auto    Verdict = "auto"    // 規則放行（唯讀工具、裝置票）
	Refused Verdict = "refused" // 擋下來了
	Errored Verdict = "error"   // 試了但壞了
)

// Entry 是鏈上的一列。欄位順序不影響摘要（canonical 會排），但型別要對。
type Entry struct {
	TS       string  `json:"ts"`
	Op       string  `json:"op"`
	Detail   string  `json:"detail"`
	Verdict  Verdict `json:"verdict"`
	ActionID *string `json:"actionId,omitempty"`
	PrevHash *string `json:"prevHash"`
	Hash     string  `json:"hash"`
}

// Log 是一個開著的稽核檔。可以並行呼叫。
type Log struct {
	mu   sync.Mutex
	file string
	last *string
	now  func() time.Time
}

// Open 開一個稽核檔，並把鏈接到既有的最後一列。
//
// 檔案讀不回來（壞掉、被人動過）**不是**從頭開始寫：那會讓一條被竄改的鏈
// 看起來像一條全新的鏈。接不上就讓 prevHash 留 null 並照實往下寫，`Verify`
// 之後指得出斷在哪裡。
func Open(file string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return nil, err
	}
	l := &Log{file: file, now: time.Now}
	if last, ok := tailHash(file); ok {
		l.last = &last
	}
	return l, nil
}

// Append 寫一列。**回傳 error，呼叫端要處理** —— 見套件說明。
func (l *Log) Append(op, detail string, v Verdict, actionID string) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	body := map[string]any{
		"ts":       l.now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"op":       op,
		"detail":   detail,
		"verdict":  string(v),
		"prevHash": nil,
	}
	if l.last != nil {
		body["prevHash"] = *l.last
	}
	var actionPtr *string
	if actionID != "" {
		body["actionId"] = actionID
		a := actionID
		actionPtr = &a
	}
	hash := canonical.SHA256Hex(canonical.JSON(body))

	e := Entry{
		TS: body["ts"].(string), Op: op, Detail: detail, Verdict: v,
		ActionID: actionPtr, PrevHash: l.last, Hash: hash,
	}
	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	f, err := os.OpenFile(l.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Entry{}, err
	}
	l.last = &hash
	return e, nil
}

// LastHash 是鏈的尾端，nil 表示這是一條新鏈。
func (l *Log) LastHash() *string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

// Result 是驗鏈的結果。
type Result struct {
	OK       bool
	Length   int
	BrokenAt int // OK 為 false 時有意義；-1 表示不適用
}

// Verify 從頭走一遍：每一列的 prevHash 要接得上前一列，而且自己的雜湊要對。
//
// **指得出是第幾列**，不是只回一個 false —— 「鏈壞了」跟「鏈在第 47 列被動過」
// 是完全不同的兩句話，而後者才查得下去。
func Verify(file string) Result {
	f, err := os.Open(file)
	if err != nil {
		if os.IsNotExist(err) {
			return Result{OK: true, Length: 0, BrokenAt: -1}
		}
		return Result{OK: false, Length: 0, BrokenAt: 0}
	}
	defer f.Close()

	var prev *string
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return Result{OK: false, Length: n + 1, BrokenAt: n}
		}
		body := map[string]any{
			"ts": e.TS, "op": e.Op, "detail": e.Detail, "verdict": string(e.Verdict), "prevHash": nil,
		}
		if e.PrevHash != nil {
			body["prevHash"] = *e.PrevHash
		}
		if e.ActionID != nil {
			body["actionId"] = *e.ActionID
		}
		if !samePtr(e.PrevHash, prev) || canonical.SHA256Hex(canonical.JSON(body)) != e.Hash {
			return Result{OK: false, Length: n + 1, BrokenAt: n}
		}
		h := e.Hash
		prev = &h
		n++
	}
	return Result{OK: true, Length: n, BrokenAt: -1}
}

func samePtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func tailHash(file string) (string, bool) {
	f, err := os.Open(file)
	if err != nil {
		return "", false
	}
	defer f.Close()
	var last string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			last = s
		}
	}
	if last == "" {
		return "", false
	}
	var e Entry
	if json.Unmarshal([]byte(last), &e) != nil || e.Hash == "" {
		return "", false
	}
	return e.Hash, true
}
