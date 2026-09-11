package devicekeys

import (
	"encoding/hex"
	"testing"
)

// base64url 的解碼必須跟 Node 一模一樣。
//
// 這不是潔癖：票上的每一段都是網路來的，而 Go 標準庫的嚴格解碼會在 Node 解得
// 出東西的地方直接失敗 —— 症狀是同一張票，TS 版說 challenge_mismatch、Go 版說
// claims_unreadable。兩個 daemon 於是不再是同一個東西。
//
// 期望值是拿 node -e 'Buffer.from(x, "base64url").toString("hex")' 實測出來的。
func TestBase64URLDecodeMatchesNode(t *testing.T) {
	for _, tc := range []struct{ in, hexOut string }{
		{"abcd", "69b71d"},
		{"abc", "69b7"},
		{"ab", "69"},
		{"a", ""},             // 剩一個字元組不出位元組，丟掉
		{"", ""},              //
		{"ab=cd", "69"},       // '=' 就是結束
		{"a!b!c!d", "69b71d"}, // 字母表以外的字元略過
		{"ab\ncd", "69b71d"},  //
		{"YQ==", "61"},        //
		{"YQ", "61"},          // 不需要 padding
		{"-_-_", "fbffbf"},    // base64url 字母表
		{"+/+/", "fbffbf"},    // 標準 base64 字母表也收
		{"YWJj====ZGVm", "616263"},
		{"Y Q", "61"},
		{"%%", ""},
		{"YWJjZA==extra", "61626364"},
	} {
		if got := hex.EncodeToString(b64urlDecode(tc.in)); got != tc.hexOut {
			t.Errorf("b64urlDecode(%q)：Node %q、Go %q", tc.in, tc.hexOut, got)
		}
	}
}
