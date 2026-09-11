// Package canonical 是「同一份資料，兩個實作算出同一個位元組串」的那一份規則。
//
// 對應 runtime/packages/ava-local-protocol/src/canonical.mjs。摘要綁在它上面：
// 核准票的 payloadHash、稽核鏈的每一列。**兩邊差一個位元組，症狀不是編譯錯誤，
// 是使用者明明按了允許卻被拒絕**，而錯誤訊息會說「payload_mismatch」，一句
// 指著錯的人的話。
//
// ## Go 的 encoding/json 有三個地方跟 JSON.stringify 不一樣
//
//  1. 它預設把 `<`、`>`、`&` 轉成 < 之類（防 HTML 注入）。JSON.stringify 不會。
//  2. `\b` 與 `\f` 的跳脫寫法不同。
//  3. map 的 key 它自己會排，但**排的是 Go 的字串順序（UTF-8 位元組）**，而
//     JSON.stringify + 我們的 sortDeep 排的是 JS 的 `<`（UTF-16 code unit）。
//     ASCII 範圍內兩者一致，超出就會分岔 —— 而機器名字、路徑裡有中文是常態。
//
// 所以這裡自己走一遍，不用 encoding/json 的 Marshal。
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// JSON 把一個值序列化成與 canonical.mjs 相同的字串。
//
// 支援的型別刻意很窄（map[string]any、[]any、string、數字、bool、nil）——
// 這是線路與稽核用的資料，不是任意物件。塞進來一個不支援的型別會 panic 而
// 不是靜靜地產生一個不一樣的摘要。
func JSON(v any) string {
	var b strings.Builder
	write(&b, v)
	return b.String()
}

// SHA256Hex 是 canonical.mjs 的 sha256Hex。
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// PayloadHash 是一次核准綁定的摘要：canonical JSON 的 sha256。
func PayloadHash(subject any) string { return SHA256Hex(JSON(subject)) }

func write(b *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, t)
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case float64:
		// JSON.stringify 對整數值的 float 不印小數點。
		if t == float64(int64(t)) {
			b.WriteString(strconv.FormatInt(int64(t), 10))
		} else {
			b.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
		}
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// **照 JS 的 `<` 排**，也就是 UTF-16 code unit 順序。Go 的字串比較是
		// UTF-8 位元組序 —— ASCII 內一樣，超出就分岔。
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			write(b, t[k])
		}
		b.WriteByte('}')
	default:
		panic(fmt.Sprintf("canonical: 不支援的型別 %T —— 摘要用的資料要先攤成基本型別", v))
	}
}

// lessUTF16 照 JavaScript 比較字串的方式比：UTF-16 code unit。
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString 照 JSON.stringify 的規則跳脫。**不跳脫 `<` `>` `&`。**
func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
