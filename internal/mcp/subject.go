// subject.go —— 一次 mcpCall 到底「被核准的是什麼」。
//
// 核准票不帶主體本身：app 那一端從它要轉發的工具呼叫算出一個摘要並簽下去，
// 這一端從收到的 frame 算一次，比對摘要。兩邊從來不交換原文，所以**序列化
// 必須逐位元組一致** —— 這個檔案是 ava-local-protocol 的 canonical.mjs 在
// Go 這一側的同一份規矩（每一層 key 排序、丟掉 undefined、沒有空白）。
//
// # 為什麼三個欄位都要綁
//
// MCP server 是使用者自己電腦上的一個程式，它能做的事沒有上界。核准卡上寫
// 的那一句話 ——「讓 <server> 跑 <tool>，參數是這些」—— 三段都必須在票裡，
// 少一段就等於卡片上的承諾沒有被票帶著走：
//
//   - server  —— 同一個工具名字在兩台 server 上是兩件完全不同的事。
//   - mcpTool —— 不叫 tool 是因為 tool 這個欄位已經被 op 名字（"mcpCall"）
//     佔走了。兩邊算的時候要給同一組欄位，否則症狀是 payload_mismatch：
//     一個看起來像「票壞了」、其實是「兩邊算的不是同一件事」的錯誤。
//   - 參數摘要 —— 走摘要不走原文：參數可以是一整份簡報的 JSON，而票要塞進
//     HTTP header 等級的地方。
package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// SubjectVersion 是主體形狀的版本，**本身就在摘要裡**：一個新的 daemon 和
// 一個舊的 app 對「主體有哪些欄位」的看法不同時，必須大聲失敗，而不是靠巧合
// 算出同一個值。
const SubjectVersion = 2

// Subject 是一次 mcpCall 的核准主體。
type Subject struct {
	Server          string
	Tool            string
	ArgumentsSHA256 string
}

// NewCallSubject 從一次呼叫算出它的核准主體。
//
// server 與 tool **用 frame 上原本那個字串**，不是查表正規化之後的 Grant.ID：
// app 是拿它送出去的那一份去簽的，這邊要是先正規化再算，兩邊算的就不是同一
// 件事（exec 的 cwd、terminalOpen 的 cwd 都踩過同一個坑）。
func NewCallSubject(server, tool string, arguments map[string]any) Subject {
	var args any = map[string]any{}
	if arguments != nil {
		args = arguments
	}
	return Subject{
		Server:          server,
		Tool:            tool,
		ArgumentsSHA256: sha256Hex(canonicalJSON(args)),
	}
}

// PayloadHash 是票綁住的那個摘要（canonical.mjs 的 payloadHash）。
func (s Subject) PayloadHash() string {
	return sha256Hex(canonicalJSON(map[string]any{
		"v":               SubjectVersion,
		"tool":            "mcpCall",
		"server":          s.Server,
		"mcpTool":         s.Tool,
		"argumentsSha256": s.ArgumentsSHA256,
	}))
}

// canonicalJSON 是兩端都算得出同一串位元組的 JSON。
//
// Go 的 encoding/json 對 map 本來就會排序 key，所以排序不用自己做；要關掉的
// 是 HTML 跳脫（JSON.stringify 不會把 < > & 變成 <，開著就兩邊不一致）。
//
// 已知還有兩處理論上的分歧，留在這裡讓下一個人省掉一次追查：Go 會跳脫
// U+2028/U+2029 而 JS 不會，以及極大的浮點數兩邊的印法不同。MCP 的參數走到
// 這兩種形狀的機率極低，而真的撞到時的症狀是 payload_mismatch —— 那是拒絕，
// 不是放行。
func canonicalJSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// 參數是從 JSON 解出來的，編不回去只可能是程式錯誤。回一個一定對不上
		// 任何票的字串，於是這次呼叫被拒絕 —— 失敗的方向是關起來。
		return "\x00unencodable"
	}
	return strings.TrimRight(buf.String(), "\n")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
