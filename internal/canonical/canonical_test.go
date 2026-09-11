package canonical

import (
	"encoding/json"
	"os"
	"testing"
)

// 語料是**拿 TS 實作真的跑出來的**（canonical.mjs 的 canonicalJson + sha256Hex），
// 不是我照著規格自己編一份。兩邊各自算、比同一個答案，分岔就是紅燈 —— 而分岔
// 在線上的症狀是「使用者明明按了允許卻被拒絕」，看起來像票壞了，其實是我們
// 兩邊算的不是同一件事。
//
// 重新產生：node /tmp/gen-canon.mjs（見 commit 訊息）

type vector struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
	JSON  string `json:"json"`
	Hash  string `json:"hash"`
}

func load(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata_vectors.json")
	if err != nil {
		t.Fatalf("語料讀不到：%v", err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("語料壞了：%v", err)
	}
	if len(vs) < 10 {
		t.Fatalf("語料只有 %d 條 —— 這條測試等於空轉", len(vs))
	}
	return vs
}

func TestMatchesTypeScript(t *testing.T) {
	for _, v := range load(t) {
		t.Run(v.Name, func(t *testing.T) {
			if got := JSON(v.Value); got != v.JSON {
				t.Fatalf("序列化分岔\n  TS: %s\n  Go: %s", v.JSON, got)
			}
			if got := SHA256Hex(v.JSON); got != v.Hash {
				t.Fatalf("摘要分岔\n  TS: %s\n  Go: %s", v.Hash, got)
			}
			if got := PayloadHash(v.Value); got != v.Hash {
				t.Fatalf("PayloadHash 分岔：%s vs %s", v.Hash, got)
			}
		})
	}
}

func TestHtmlCharactersAreNotEscaped(t *testing.T) {
	// Go 的 encoding/json 預設會把這三個轉成 < 之類。用它就分岔。
	if got := JSON(map[string]any{"q": "a<b>c&d"}); got != `{"q":"a<b>c&d"}` {
		t.Fatalf("HTML 字元被跳脫了：%s", got)
	}
}

func TestKeysSortByUtf16NotBytes(t *testing.T) {
	// JS 的 `<` 比的是 UTF-16 code unit，Go 的字串比較是 UTF-8 位元組序。
	// ASCII 內一樣，超出就分岔 —— 而機器名字、路徑裡有中文是常態。
	got := JSON(map[string]any{"機器": 1, "apple": 2, "Zebra": 3})
	want := `{"Zebra":3,"apple":2,"機器":1}`
	if got != want {
		t.Fatalf("排序分岔\n  want %s\n  got  %s", want, got)
	}
}

func TestUnsupportedTypePanicsInsteadOfDiverging(t *testing.T) {
	// 靜靜地產生一個不一樣的摘要，比當掉糟得多：前者要等到使用者按了允許
	// 被拒絕才會有人發現。
	defer func() {
		if recover() == nil {
			t.Fatal("不支援的型別沒有當掉 —— 它會安靜地算出一個錯的摘要")
		}
	}()
	JSON(map[string]any{"t": struct{ A int }{1}})
}
