package host

import (
	"testing"

	"github.com/UnieAI/Rabi-local/internal/canonical"
)

// subject_test.go —— 核准主體算出來的東西，跟 app 那一側**逐位元組相同**。
//
// 下面的 json 與 hash 是用真的 canonical.mjs 跑出來的，不是照規格自己編：
//
//	cd runtime/packages/ava-local-protocol/src
//	node -e 'import("./canonical.mjs").then(m=>{
//	  const s = m.approvalSubject("exec", {command:"ls -la", kind:"bash", cwd:null, env:{}, sandbox:false});
//	  console.log(m.canonicalJson(s), m.payloadHash(s));
//	})'
//
// 為什麼一定要這樣測：兩邊從來不交換主體本身，各自算摘要然後比。差一個位元組的
// 症狀不是編譯錯誤，是**使用者明明按了允許卻被拒絕**，而錯誤訊息會說
// payload_mismatch —— 一句指著錯的人的話。
func TestSubjectsMatchCanonicalMjs(t *testing.T) {
	cases := []struct {
		name    string
		subject map[string]any
		json    string
		hash    string
	}{
		{
			name:    "exec／最普通的一條",
			subject: execSubject("ls -la", "bash", "", nil, false),
			json:    `{"command":"ls -la","cwd":null,"env":{},"kind":"bash","sandbox":false,"tool":"exec","v":2}`,
			hash:    "f9630729d2538de8168e3b742e77aa73e913589c088762ed3ac8f44c2b21c8d3",
		},
		{
			// 中文、`<` `&` `>`、以及兩個順序相反的環境變數 —— 三個 Go 跟
			// JSON.stringify 最容易分岔的地方各一個。
			name:    "exec／中文、跳脫、環境變數排序",
			subject: execSubject("echo 你好 <&>", "python", "/w/專案", map[string]string{"B": "2", "A": "1"}, true),
			json:    `{"command":"echo 你好 <&>","cwd":"/w/專案","env":{"A":"1","B":"2"},"kind":"python","sandbox":true,"tool":"exec","v":2}`,
			hash:    "64602f99a131dcd3ebfd537c4224d82c08b11bbfd2ad63be7378a0f46453d538",
		},
		{
			name:    "writeFile／綁的是內容的摘要，不是內容",
			subject: writeFileSubject("a/b.txt", []byte("hello")),
			json:    `{"contentSha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","path":"a/b.txt","tool":"writeFile","v":2}`,
			hash:    "46e871e129f410dd20b09a1983bc14f0b98aec0c007d36aa48ff82a230f0be35",
		},
		{
			name:    "deleteFile",
			subject: pathSubject("deleteFile", "x/y"),
			json:    `{"path":"x/y","tool":"deleteFile","v":2}`,
			hash:    "1cc3488edb692c31220b9d624cafbc883a5e41e39f124a1414ce1c4522309ad6",
		},
		{
			name:    "ensureDir",
			subject: pathSubject("ensureDir", "x/y"),
			json:    `{"path":"x/y","tool":"ensureDir","v":2}`,
			hash:    "4ecf7d2f30c114bf344b72157f5f0723e7482a2f0fdbc41fb075c33f8e2e2cd0",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := canonical.JSON(c.subject); got != c.json {
				t.Fatalf("序列化分岔了：\n  這一側 %s\n  app 那側 %s", got, c.json)
			}
			if got := canonical.PayloadHash(c.subject); got != c.hash {
				t.Fatalf("摘要分岔了：%s，應該是 %s", got, c.hash)
			}
		})
	}
}

// 票綁的是 frame 上**原本那個字串**，不是我們解析之後的絕對路徑。
//
// 這是最容易做錯、而且錯了會看起來像別的問題的一點：app 簽票的時候手上只有它送
// 出去的那個字串，daemon 這一側先解析再算的話，兩邊算的就不是同一件事。
func TestExecBindsTheStringOnTheWireNotTheResolvedPath(t *testing.T) {
	h := newHarness(t)
	h.call("exec", map[string]any{"command": "ls", "cwd": "sub/../"}, goodTicket)

	if len(h.gate.asked) != 1 {
		t.Fatalf("閘門沒有被問到：%v", h.gate.asked)
	}
	want := canonical.PayloadHash(execSubject("ls", "bash", "sub/../", nil, false))
	if h.gate.asked[0].PayloadHash != want {
		t.Fatal("摘要不是照 frame 上那個 cwd 算的 —— 症狀會是 payload_mismatch")
	}
}

// 每一個會改東西的欄位都要在票裡：改掉任何一個，摘要就必須不同。
// 否則一張真票可以被**第一次**用在不同的周邊條件上（那不是重放，nonce 擋不到）。
func TestEveryFieldThatChangesTheOutcomeIsBound(t *testing.T) {
	base := execSubject("npm test", "bash", "/w", map[string]string{}, false)
	variants := map[string]map[string]any{
		"換一條指令":   execSubject("npm publish", "bash", "/w", map[string]string{}, false),
		"換一個資料夾":  execSubject("npm test", "bash", "/other", map[string]string{}, false),
		"換一種直譯器":  execSubject("npm test", "python", "/w", map[string]string{}, false),
		"塞一個環境變數": execSubject("npm test", "bash", "/w", map[string]string{"PATH": "/evil"}, false),
		"改掉沙盒承諾":  execSubject("npm test", "bash", "/w", map[string]string{}, true),
	}
	baseHash := canonical.PayloadHash(base)
	for name, v := range variants {
		if canonical.PayloadHash(v) == baseHash {
			t.Fatalf("%s 之後摘要沒有變 —— 那張票會在改過的條件下照樣通過", name)
		}
	}
}
