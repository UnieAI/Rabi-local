package mcp

import "testing"

// 核准主體的摘要是**兩個不同語言的實作各算一次、然後比對**的東西，所以這裡
// 的期望值不是我算的，是拿 TypeScript 那一份（ava-local-protocol 的
// canonical.mjs）跑出來的：
//
//	approvalSubject("mcpCall", { server: "slidework", tool: "publish_deck",
//	  arguments: { b: 1, a: "<x>&y", nested: { z: true, y: [3, "2"] } } })
//
// 參數裡刻意放了 `<` 與 `&`：Go 的 encoding/json 預設會把它們跳脫成 <，
// 而 JSON.stringify 不會 —— 沒關掉的話兩邊永遠算不出同一個摘要，症狀是使用者
// 明明按了允許卻得到 payload_mismatch。
func TestSubjectMatchesTypeScript(t *testing.T) {
	args := map[string]any{
		"b":      float64(1),
		"a":      "<x>&y",
		"nested": map[string]any{"z": true, "y": []any{float64(3), "2"}},
	}
	s := NewCallSubject("slidework", "publish_deck", args)

	const wantArgs = "09b289afcb2f37893d27df999267dde2aef2a934b120f72e4986d175a9f26064"
	const wantPayload = "9a126dd921f97193b5d25d64ba7c4c4f5a66c2bf8e81004267e0ab8e70a33005"
	if s.ArgumentsSHA256 != wantArgs {
		t.Errorf("參數摘要 = %s，TypeScript 那一份算出來是 %s", s.ArgumentsSHA256, wantArgs)
	}
	if got := s.PayloadHash(); got != wantPayload {
		t.Errorf("主體摘要 = %s，TypeScript 那一份算出來是 %s", got, wantPayload)
	}
}

func TestSubjectIgnoresKeyOrder(t *testing.T) {
	a := NewCallSubject("s", "t", map[string]any{"x": 1.0, "y": 2.0})
	b := NewCallSubject("s", "t", map[string]any{"y": 2.0, "x": 1.0})
	if a.ArgumentsSHA256 != b.ArgumentsSHA256 {
		t.Fatal("key 的順序換了就算出不同的摘要 —— 那會讓真的核准過的呼叫被拒絕")
	}
}

func TestSubjectBindsAllThree(t *testing.T) {
	base := NewCallSubject("slidework", "publish_deck", map[string]any{"deck": "q3"})
	// 換 server、換工具、換參數，三者任一改變都必須是不同的主體，否則核准卡
	// 上寫的那句話沒有被票帶著走。
	for _, other := range []Subject{
		NewCallSubject("other", "publish_deck", map[string]any{"deck": "q3"}),
		NewCallSubject("slidework", "delete_deck", map[string]any{"deck": "q3"}),
		NewCallSubject("slidework", "publish_deck", map[string]any{"deck": "q4"}),
	} {
		if other.PayloadHash() == base.PayloadHash() {
			t.Fatalf("%+v 和 %+v 算出同一個摘要", base, other)
		}
	}
}
