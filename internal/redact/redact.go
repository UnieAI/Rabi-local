// Package redact 在祕密離開這台機器之前把它蓋掉。
//
// 這是 runtime/apps/ava-local/src/redact.ts 的 Go 版，行為逐條等價 ——
// 兩邊共用同一份語料（runtime/apps/ava-local/test/redact-corpus.json），
// 見 redact_test.go。改規則就要兩邊一起改，並重跑語料產生器。
//
// # 為什麼在 daemon 這一端做
//
// 指令的輸出和讀到的檔案內容，原樣經過 relay → app → 引擎 → 模型供應商。
// 也就是說 `cat .env` 一次，那些值就同時進了我們的資料庫和第三方的脈絡裡。
// 這條路上只有這裡還在使用者自己的機器上，別的地方都已經離開了。
//
// # 這是安全網，不是邊界
//
// 說清楚才不會被拿去當保證：一個**刻意**要把祕密送出去的程式，只要 base64
// 一下、或者一個字元一個字元印，這裡就攔不住。它擋的是**意外** —— agent 為了
// 做別的事去讀一個設定檔、一個指令順手把 token 印在錯誤訊息裡。
//
// 所以：有了這一層，該關押的還是要關押（scope、核准、confine 都不能因此放鬆），
// 對外也只能說「降低意外外洩的量」，不能說「祕密出不去」。
//
// # 規則：寧可漏抓，不可誤抓
//
// 這裡只認**有形狀的東西**：已知前綴的金鑰、JWT、私鑰區塊、帶密碼的連線字串、
// `password=` 這種賦值、過得了 Luhn 的卡號。
//
// 刻意**不**做「看起來很亂又很長的字串就蓋掉」。那種規則會把 git 的 SHA、
// base64 的圖、minified 的 JS 全部蓋掉，於是 agent 讀到的檔案是壞的，而它不會
// 說「這裡被蓋掉了」，它會照著壞掉的內容繼續做事。一個會默默破壞正常工作的
// 安全功能，最後一定會被關掉。
//
// 蓋掉的地方留一個看得懂的記號（`[redacted:aws-key]`），有兩個用處：模型知道
// 這裡本來有東西、不會以為是空的；使用者看到之後知道要自己去看那個檔案。
//
// # 效能
//
// 這條路跑在每一次指令輸出上。Go 的 regexp 是 RE2，沒有回溯，最壞情況是輸入
// 長度的線性時間 —— 所以這裡不會有災難性回溯，規則也不必為了躲回溯而寫歪。
package redact

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Kind 是一種被認得的祕密形狀。字串值同時是記號裡的名字（`[redacted:<kind>]`），
// 兩邊（TS/Go）與稽核紀錄用的是同一組名字。
type Kind string

const (
	KindPrivateKey     Kind = "private-key"
	KindJWT            Kind = "jwt"
	KindOpenAIKey      Kind = "openai-key"
	KindGitHubToken    Kind = "github-token"
	KindAWSKey         Kind = "aws-key"
	KindGoogleKey      Kind = "google-key"
	KindSlackToken     Kind = "slack-token"
	KindBearer         Kind = "bearer"
	KindURLCredentials Kind = "url-credentials"
	KindAssignment     Kind = "assignment"
	KindCardNumber     Kind = "card-number"
)

// Result 是一次遮蔽的結果。
type Result struct {
	// Text 是蓋過之後、可以送出去的文字。
	Text string
	// Found 是蓋掉了幾個、各是什麼。給稽核用 —— 蓋掉這件事本身要留下紀錄。
	// 沒蓋到任何東西時是一個空 map（不是 nil）。
	Found map[Kind]int
}

// Mask 是某一種形狀留在原地的記號。
func Mask(k Kind) string { return "[redacted:" + string(k) + "]" }

// DefaultCarry 是串流遮蔽預設留多長的尾巴（位元組）。跟 TS 版一樣是 256。
const DefaultCarry = 256

// rule 是一條規則。replace 為 nil 時整段換成記號；否則由 replace 決定要留下什麼。
type rule struct {
	kind    Kind
	re      *regexp.Regexp
	replace func(src string, idx []int) string
}

// group 取出第 n 個括號的內容；沒有參與比對時回 ok=false。
// （JS 那邊是 undefined，Go 這邊是索引 -1 —— 賦值規則要靠這個分辨是哪一種引號。）
func group(src string, idx []int, n int) (string, bool) {
	if 2*n+1 >= len(idx) || idx[2*n] < 0 {
		return "", false
	}
	return src[idx[2*n]:idx[2*n+1]], true
}

// rules 的順序有意義：先吃掉整塊的（私鑰、連線字串），再吃單一 token。
// 反過來的話，`postgres://u:p@h/db` 裡的密碼會先被當成別的東西咬掉一半。
var rules = []rule{
	{
		kind: KindPrivateKey,
		// (?s) 讓 . 吃得下換行，等同 TS 的 [\s\S]；.*? 是非貪婪，一塊一塊吃。
		re: regexp.MustCompile(`(?s)-----BEGIN[ A-Z]*PRIVATE KEY-----.*?-----END[ A-Z]*PRIVATE KEY-----`),
	},
	{
		// `scheme://user:password@host` —— 只蓋密碼那一段，主機和使用者留著，
		// 因為 agent 常常需要那兩個來判斷它在跟哪一個服務講話。
		kind: KindURLCredentials,
		re:   regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)([^/\s@]+)(@)`),
		replace: func(src string, idx []int) string {
			head, _ := group(src, idx, 1)
			tail, _ := group(src, idx, 3)
			return head + Mask(KindURLCredentials) + tail
		},
	},
	{kind: KindJWT, re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{kind: KindOpenAIKey, re: regexp.MustCompile(`\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}\b`)},
	{kind: KindGitHubToken, re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)},
	{kind: KindAWSKey, re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	// 長度放寬（文件上是 35，但格式會漂）。`AIza` 這個前綴本身就夠獨特，
	// 精準度由前綴撐著，長度不必卡死 —— 卡死的代價是一把真的金鑰整把送出去。
	{kind: KindGoogleKey, re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,45}\b`)},
	{kind: KindSlackToken, re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{
		kind: KindBearer,
		re:   regexp.MustCompile(`\b([Bb]earer\s+)([A-Za-z0-9._~+/=-]{20,})`),
		replace: func(src string, idx []int) string {
			head, _ := group(src, idx, 1)
			return head + Mask(KindBearer)
		},
	},
	{
		// `password = "…"`、`api_key: …`、`SECRET=…`
		// 值可能有引號也可能沒有；沒引號時吃到空白或行尾為止。
		// **鍵名留著**：agent 要知道這個設定存在，只是不知道它的值。
		kind: KindAssignment,
		re: regexp.MustCompile(`(?i)\b((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|` +
			`auth[_-]?token|client[_-]?secret)\s*[:=]\s*)(?:"([^"\n]{4,})"|'([^'\n]{4,})'|([^\s"',;]{4,}))`),
		replace: func(src string, idx []int) string {
			head, _ := group(src, idx, 1)
			quote := ""
			if _, ok := group(src, idx, 2); ok {
				quote = `"`
			} else if _, ok := group(src, idx, 3); ok {
				quote = "'"
			}
			return head + quote + Mask(KindAssignment) + quote
		},
	},
}

// cardRe 先粗篩出「像卡號的一串數字」，真正決定蓋不蓋的是 Luhn。
var cardRe = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)

// luhnOK 檢查卡號的檢查碼。卡號要過這一關才蓋 ——
// 不然訂單編號、序號會被當成卡號蓋掉。
func luhnOK(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i]) - '0'
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

var cardSep = strings.NewReplacer(" ", "", "-", "")

// applyRule 把一條規則套過整段文字，回傳換過之後的文字，並累加次數。
// 掃描方式跟 JS 的 /g 一樣：由左到右、不重疊。
func applyRule(text string, r rule, found map[Kind]int) string {
	matches := r.re.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, m := range matches {
		b.WriteString(text[last:m[0]])
		if r.replace != nil {
			b.WriteString(r.replace(text, m))
		} else {
			b.WriteString(Mask(r.kind))
		}
		found[r.kind]++
		last = m[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

// Redact 把一段文字裡的祕密蓋掉。純函式：同樣的輸入永遠同樣的輸出。
//
// 這是給「一次拿到完整內容」的地方用的（例如讀檔的結果）。指令輸出那種
// 一塊一塊來的，要用 NewStream —— 不然金鑰會被切在兩塊中間漏出去。
func Redact(input string) Result {
	found := map[Kind]int{}
	if input == "" {
		return Result{Text: input, Found: found}
	}
	text := input
	for _, r := range rules {
		text = applyRule(text, r, found)
	}

	// 卡號單獨處理：粗篩到的要過 Luhn 才蓋，過不了的原樣留著。
	text = cardRe.ReplaceAllStringFunc(text, func(m string) string {
		digits := cardSep.Replace(m)
		if len(digits) < 13 || len(digits) > 19 || !luhnOK(digits) {
			return m
		}
		found[KindCardNumber]++
		return Mask(KindCardNumber)
	})

	return Result{Text: text, Found: found}
}

// Stream 是串流版的遮蔽器：指令的輸出是一塊一塊來的，而一把金鑰**會被切在
// 兩塊中間**。
//
// 逐塊套規則的話，被切開的那一把兩邊都比對不到，於是完整地送出去 —— 而且這種
// 漏法跟輸出的節奏有關，測起來時好時壞，是最難發現的那一種。
//
// 所以留一段尾巴：每一塊的最後 carry 個位元組先不送，等下一塊接上去再一起比。
// 尾巴只在**沒有換行可以切**的時候才留滿 —— 祕密幾乎不跨行，所以切在最後一個
// 換行處既安全又能讓輸出即時。
//
// 兩個一定要記得的事：
//   - 串流結束一定要呼叫 Flush，不然最後一段永遠不會被檢查，也永遠不會送出去。
//   - carry 是一個界線，不是保證：比 carry 還長、又完全沒有換行的祕密會漏。
//     （語料裡的 carry-too-small-leaks 就是把這個界線本身釘住。）
//
// Stream 不是 goroutine-safe：一條輸出串流配一個 Stream，由那條串流自己的
// goroutine 使用。
type Stream struct {
	carry   int
	pending string
	found   map[Kind]int
}

// NewStream 開一個串流遮蔽器，尾巴長度用預設的 DefaultCarry。
func NewStream() *Stream { return NewStreamWithCarry(DefaultCarry) }

// NewStreamWithCarry 開一個串流遮蔽器並指定尾巴留多長（位元組）。
// carry <= 0 一律當成 DefaultCarry —— 留 0 等於整個保護關掉，不給這個選項。
func NewStreamWithCarry(carry int) *Stream {
	if carry <= 0 {
		carry = DefaultCarry
	}
	return &Stream{carry: carry, found: map[Kind]int{}}
}

// Push 餵進下一塊，回傳這一次可以安全送出去的部分（可能是空字串）。
func (s *Stream) Push(chunk string) string {
	s.pending += chunk

	// 切點：最後一個換行之後的東西留著；沒有換行就留最後 carry 個位元組。
	cut := 0
	if nl := strings.LastIndexByte(s.pending, '\n'); nl >= 0 {
		cut = nl + 1
	} else if len(s.pending) > s.carry {
		cut = len(s.pending) - s.carry
	}
	// Go 的字串是位元組，切點可能正好落在一個多位元組字元中間 ——
	// 那會讓送出去的那一半變成壞掉的 UTF-8（中文輸出會看到亂碼）。
	// 往前退到字元的開頭。TS 版沒有這一步，因為它的 slice 是以字元為單位的。
	for cut > 0 && cut < len(s.pending) && !utf8.RuneStart(s.pending[cut]) {
		cut--
	}
	if cut <= 0 {
		return ""
	}

	head := s.pending[:cut]
	s.pending = s.pending[cut:]
	r := Redact(head)
	s.tally(r.Found)
	return r.Text
}

// PushBytes 跟 Push 一樣，只是收 []byte —— runner 那邊拿到的就是 []byte。
//
// 注意：一塊 []byte 的結尾可能正好切在一個多位元組字元中間。那半個字元會被
// 留在尾巴裡等下一塊接上來，所以只要最後有 Flush，內容不會壞掉。
func (s *Stream) PushBytes(chunk []byte) string { return s.Push(string(chunk)) }

// Flush 在串流結束時把留著的尾巴處理完吐出來。不呼叫的話最後一段會整段不見。
func (s *Stream) Flush() string {
	if s.pending == "" {
		return ""
	}
	r := Redact(s.pending)
	s.tally(r.Found)
	s.pending = ""
	return r.Text
}

// Found 回報這條串流到目前為止總共蓋掉了什麼。給稽核用。
func (s *Stream) Found() map[Kind]int {
	out := make(map[Kind]int, len(s.found))
	for k, v := range s.found {
		out[k] = v
	}
	return out
}

func (s *Stream) tally(f map[Kind]int) {
	for k, n := range f {
		s.found[k] += n
	}
}
