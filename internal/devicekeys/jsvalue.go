package devicekeys

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// 這個檔案只有一個任務：**讓 Go 這邊看到的 JSON 跟 Node 那邊看到的一模一樣。**
//
// 線路上的東西全部是攻擊者控制得了的，所以「Go 比較嚴格、直接解不出來」不是
// 安全，是**分歧**：同一張票 TS 說 wrong_machine、Go 說 claims_unreadable，那
// 兩個 daemon 就不再是同一個東西，而差分測試會紅在一個看起來無關的地方。
//
// 所以這裡刻意模仿 Node 的寬鬆：base64url 濾掉字母表以外的字元、數字一律走
// float64（JSON.parse 的語意）、型別不對就當成「沒有這個欄位」而不是錯誤。

// b64urlDecode 照 Node 的 `Buffer.from(s, "base64url")` 解碼。
//
// Node 的解碼器**不會失敗**：字母表以外的字元直接略過（'a!b!c!d' 解得出
// 'abcd'）、'=' 當成結束、base64 與 base64url 兩套字母表都收、長度不足 4 的
// 尾巴盡量解、剩一個字元就丟掉。Go 標準庫的解碼器每一條都相反，所以這裡自己
// 寫一份 —— 實測過 16 組邊界輸入，兩邊逐位元組相同。
func b64urlDecode(s string) []byte {
	// 先過濾成純字母表，順便把 base64url 的 -_ 折回 +/
	filtered := make([]byte, 0, len(s))
scan:
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '=':
			// padding 就是結束，後面全部不看（Node 如此）
			break scan
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			filtered = append(filtered, c)
		case c == '+' || c == '-':
			filtered = append(filtered, '+')
		case c == '/' || c == '_':
			filtered = append(filtered, '/')
		default:
			// 其餘（空白、標點、UTF-8 位元組）一律略過
		}
	}
	// 補回標準 base64 的 padding，讓標準庫解得動；剩 1 個字元的尾巴丟掉
	// （那不足以組出任何一個位元組，Node 也是丟掉）。
	if n := len(filtered) % 4; n == 1 {
		filtered = filtered[:len(filtered)-1]
	} else if n != 0 {
		filtered = append(filtered, strings.Repeat("=", 4-n)...)
	}
	out, err := base64.StdEncoding.DecodeString(string(filtered))
	if err != nil {
		return nil
	}
	return out
}

// b64urlEncode 對應 Node 的 `buf.toString("base64url")`（無 padding）。
func b64urlEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// parseJSON 對應 `JSON.parse(buf.toString("utf8"))`。
//
// 兩個細節是為了跟 Node 對齊：
//   - `toString("utf8")` 會把壞掉的 UTF-8 換成 U+FFFD，Go 的 string() 不會，
//     所以這裡先 ToValidUTF8；
//   - 數字走 json.Number 再自己轉 float64，因為 JSON.parse 的數字就是 float64
//     （1e400 會變成 Infinity，而 Infinity 在時間檢查那裡是「不是有限數」）。
func parseJSON(raw []byte) (any, bool) {
	text := strings.ToValidUTF8(string(raw), "�")
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	// JSON.parse 不接受尾巴還有東西（"{} x"），Go 的 Decoder 預設接受，補一刀。
	var tail any
	if err := dec.Decode(&tail); err == nil {
		return nil, false
	}
	return v, true
}

// jsField 取出一個欄位；不是物件、或沒有這個欄位，回 nil。
func jsField(v any, key string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m[key]
}

// jsString 取出一個**字串型別**的欄位。
//
// 回傳的 ok=false 涵蓋「沒有這個欄位」與「有但不是字串」兩種 —— 對應 JS 的
// `claims.machineId !== expect.machineId`：期望值一定是字串，所以非字串的一方
// 在嚴格比較下必然不等。
func jsString(v any, key string) (string, bool) {
	s, ok := jsField(v, key).(string)
	return s, ok
}

// jsNumber 取出一個數字欄位，並回報它是不是**有限**數（Number.isFinite）。
func jsNumber(v any, key string) (float64, bool) {
	n, ok := jsField(v, key).(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil {
		// 超出 float64 範圍的字面值：JS 會變成 ±Infinity，也就是「不是有限數」
		if strings.Contains(err.Error(), "value out of range") {
			return math.Inf(1), false
		}
		return 0, false
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return f, false
	}
	return f, true
}

// jsStrictEqualNumber 對應 JS 的 `x === 1` —— 型別要對，值要對。
func jsStrictEqualNumber(v any, key string, want float64) bool {
	f, ok := jsNumber(v, key)
	return ok && f == want
}

// jsToString 對應 JS 的 `String(x ?? "")`。
//
// 只有 asAssertion 用得到：frame 上那個 `by` 是網路來的，什麼形狀都可能，而
// **有給就一定要走簽章那條路**。少了這個正規化，一個亂寫的 by 會變成 falsy，
// 於是掉進「本機當面確認」那一條 —— 那是一條把註冊送給任何人的捷徑。
func jsToString(v any) string {
	switch t := v.(type) {
	case nil:
		return "" // `null ?? ""` → ""；`undefined ?? ""` → ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case json.Number:
		return t.String()
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			if e == nil {
				parts[i] = ""
			} else {
				parts[i] = jsToString(e)
			}
		}
		return strings.Join(parts, ",")
	default:
		return "[object Object]"
	}
}
