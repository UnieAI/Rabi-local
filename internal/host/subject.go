package host

import (
	"github.com/UnieAI/Rabi-local/internal/canonical"
)

// subject.go —— 「使用者到底批准了什麼」，攤成一份兩邊都算得出來的資料。
//
// 逐欄對應 runtime/packages/ava-local-protocol/src/canonical.mjs 的
// approvalSubject。序列化與摘要交給 internal/canonical —— **那是唯一的一份規則**，
// 這裡只負責說「這個 op 的主體有哪些欄位」。
//
// # 一條貫穿全部的規矩：綁的是 frame 上的原字串
//
// app 簽票的時候手上只有它送出去的那幾個字串。daemon 這一側如果拿解析之後的
// 絕對路徑（symlink 被解開、結尾的斜線被清掉、相對路徑被接上 root）去算摘要，
// 兩邊算的就不是同一件事，而症狀是 payload_mismatch —— 一個看起來像「票壞了」
// 其實是「我們簽錯了東西」的錯誤。exec 的 cwd、terminalOpen 的 cwd、mcpCall 的
// server 三個地方都踩過同一顆雷。

// ApprovalSubjectVersion 是 subject 形狀的版本，而且它**在摘要裡面**：兩邊對
// 「一個 subject 有哪些欄位」的理解不一致時，必須大聲失敗，而不是碰巧一致。
const ApprovalSubjectVersion = 2

// execSubject 是一次 exec 的核准主體。
//
// # 為什麼綁的不只是那串指令
//
// 每一個「daemon 會讀、而且會改變結果」的欄位都必須在票裡，否則卡片上的承諾
// 沒有被票帶著走。這不是防重放（nonce 管那個），是防**一張真票第一次被用在
// 不同的周邊條件上**，而做得到這件事的正是這套設計不信任的那個元件：
//
//   - env     —— 正常路徑上一個都不送，所以綁它不花任何成本；一個被塞進去的
//     PATH 會讓一條核准過的 `npm test` 跑的是別人的 npm。
//   - cwd     —— 卡片上寫的是一條指令，不是一個地方。
//   - kind    —— 同一段文字走 python3 -c 是另一個程式。
//   - sandbox —— 卡片上**用文字**承諾了這一件事。一個給人看過、票卻沒有帶著的
//     承諾，不是承諾。
func execSubject(command, kind, cwd string, env map[string]string, sandbox bool) map[string]any {
	return map[string]any{
		"v":       ApprovalSubjectVersion,
		"tool":    "exec",
		"command": command,
		"kind":    normaliseKind(kind),
		// 空字串等同沒有給 —— canonical.mjs 的 `args.cwd ? args.cwd : null`。
		"cwd":     nilIfEmptyAny(cwd),
		"env":     envAny(env),
		"sandbox": sandbox,
	}
}

// writeFileSubject 綁的是路徑與內容的**摘要**，不是內容本身：一次寫入可以是
// 好幾 MB，而票要塞進 HTTP header 等級的地方。
func writeFileSubject(path string, content []byte) map[string]any {
	return map[string]any{
		"v":             ApprovalSubjectVersion,
		"tool":          "writeFile",
		"path":          path,
		"contentSha256": canonical.SHA256Hex(string(content)),
	}
}

// pathSubject 是 deleteFile 與 ensureDir 的主體：只有一個路徑。
func pathSubject(tool, path string) map[string]any {
	return map[string]any{
		"v":    ApprovalSubjectVersion,
		"tool": tool,
		"path": path,
	}
}

// normaliseKind 跟 canonical.mjs 一樣：只有 "python" 是 python，其餘都是 bash。
// **兩邊要正規化成同一個字**，否則 subject 不同，症狀是 payload_mismatch。
func normaliseKind(kind string) string {
	if kind == "python" {
		return "python"
	}
	return "bash"
}

// envAny 把環境變數攤成 canonical 收得下的形狀。**nil 也要是一個空物件** ——
// canonical.mjs 的 approvalSubject 沒有 env 的時候送的是 `{}`，不是 `null`。
func envAny(env map[string]string) map[string]any {
	out := make(map[string]any, len(env))
	for k, v := range env {
		out[k] = v
	}
	return out
}

func nilIfEmptyAny(s string) any {
	if s == "" {
		return nil
	}
	return s
}
