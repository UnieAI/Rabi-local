package terminal

import "testing"

// TestApprovalSubjectMatchesProtocol 是這個套件裡最重要的一個測試。
//
// 下面那幾組期望值**不是我算的**，是用 TypeScript 那一側真正在用的
// runtime/packages/ava-local-protocol/src/canonical.mjs 跑出來的：
//
//	node -e 'import("./canonical.mjs").then(m => {
//	  const s = m.approvalSubject("terminalOpen", { cwd: "/home/roy/work" });
//	  console.log(m.canonicalJson(s), m.payloadHash(s));
//	})'
//
// 兩邊算的不是同一件事的時候，症狀是 payload_mismatch —— 一個看起來像
// 「票壞了」其實是「我們簽錯了東西」的錯誤。這個測試就是那件事的紅線：
// 改了 ApprovalSubject 而沒有同步改 canonical.mjs（或反過來），這裡會紅。
func TestApprovalSubjectMatchesProtocol(t *testing.T) {
	cases := []struct {
		name      string
		cwd       string
		env       map[string]string
		canonical string
		hash      string
	}{
		{
			name:      "沒有 cwd 也沒有 env",
			canonical: `{"cwd":null,"env":{},"tool":"terminalOpen","v":2}`,
			hash:      "45e1b9775c63a00000078248a5daccf968b380ee1de6d243e71322fc3ce7ebb0",
		},
		{
			name:      "只有 cwd",
			cwd:       "/home/roy/work",
			canonical: `{"cwd":"/home/roy/work","env":{},"tool":"terminalOpen","v":2}`,
			hash:      "5ca2f175908099aa3e909c8b0603d2ea7beca1c3b8682017ba01f4df54608fc7",
		},
		{
			name:      "cwd 加 env（key 要排序）",
			cwd:       "/home/roy/work",
			env:       map[string]string{"B": "2", "A": "1"},
			canonical: `{"cwd":"/home/roy/work","env":{"A":"1","B":"2"},"tool":"terminalOpen","v":2}`,
			hash:      "778f0e19c1cbdc1c68b79f31a3a90a728c10802e6c57bdec7be66b1019078068",
		},
		{
			// JS 的 `args.cwd ? args.cwd : null` —— 空字串等同沒有給。
			name:      "空字串的 cwd 等於 null",
			cwd:       "",
			canonical: `{"cwd":null,"env":{},"tool":"terminalOpen","v":2}`,
			hash:      "45e1b9775c63a00000078248a5daccf968b380ee1de6d243e71322fc3ce7ebb0",
		},
		{
			name:      "env 的 key 照 UTF-16 碼元排，不是插入順序",
			env:       map[string]string{"Z": "z", "a": "1", "1": "9"},
			canonical: `{"cwd":null,"env":{"1":"9","Z":"z","a":"1"},"tool":"terminalOpen","v":2}`,
			hash:      "bcb67d3f66ef07adce200bfa1a3c9c2047b698b62c5f1f9aa86238e66f88db61",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := string(ApprovalSubject(c.cwd, c.env)); got != c.canonical {
				t.Errorf("canonical JSON 不一樣：\n got %s\nwant %s", got, c.canonical)
			}
			if got := ApprovalPayloadHash(c.cwd, c.env); got != c.hash {
				t.Errorf("摘要不一樣：\n got %s\nwant %s", got, c.hash)
			}
		})
	}
}

// TestJSONStringEscaping 盯住 Go 跟 JSON.stringify 不一樣的那幾個地方。
func TestJSONStringEscaping(t *testing.T) {
	cases := map[string]string{
		// encoding/json 預設會把這三個轉義成 \u003c 之類，JSON.stringify 不會。
		`<a>&b`: `"<a>&b"`,
		// 這兩個 encoding/json 寫成 \u0008 / \u000c，JSON.stringify 寫短的。
		"\b\f":        `"\b\f"`,
		"\n\r\t":      `"\n\r\t"`,
		"\x00":        `"\u0000"`,
		`quote"back\`: `"quote\"back\\"`,
		"中文/日本語":      `"中文/日本語"`,
	}
	for in, want := range cases {
		if got := jsonString(in); got != want {
			t.Errorf("jsonString(%q) = %s，想要 %s", in, got, want)
		}
	}
}

// TestVerifyFailsClosed —— 沒有接驗證器、或沒有附票，一律拒絕。
func TestVerifyFailsClosed(t *testing.T) {
	s := New(Options{Root: t.TempDir()})
	if _, err := s.verify(OpenRequest{Approval: "anything"}); CodeOf(err) != CodeApprovalReq {
		t.Fatalf("沒有驗證器應該回 %s，得到 %v", CodeApprovalReq, err)
	}

	s = New(Options{Root: t.TempDir(), Approval: GateFunc(func(_, _, _ string) (string, error) {
		t.Fatal("沒有票的時候不該去問驗證器")
		return "", nil
	})})
	if _, err := s.verify(OpenRequest{}); CodeOf(err) != CodeApprovalReq {
		t.Fatalf("沒有票應該回 %s，得到 %v", CodeApprovalReq, err)
	}
}

// TestVerifyBindsRawCwd —— 交給驗證器的摘要，綁的是**請求裡的原字串**。
//
// 這是整條路上最容易做錯的一步：如果哪天有人把解析過的絕對路徑餵進去，
// app 那一側簽的票就永遠對不上。
func TestVerifyBindsRawCwd(t *testing.T) {
	var seenTool, seenHash string
	s := New(Options{Root: "/granted", Approval: GateFunc(func(tool, hash, _ string) (string, error) {
		seenTool, seenHash = tool, hash
		return "action-1", nil
	})})
	req := OpenRequest{Cwd: "sub/dir", Env: map[string]string{"A": "1"}, Approval: "ticket"}
	actionID, err := s.verify(req)
	if err != nil {
		t.Fatalf("不該失敗：%v", err)
	}
	if actionID != "action-1" {
		t.Errorf("actionID 應該原樣帶回來，得到 %q", actionID)
	}
	if seenTool != "terminalOpen" {
		t.Errorf("tool 應該是 terminalOpen，得到 %q", seenTool)
	}
	if want := ApprovalPayloadHash("sub/dir", map[string]string{"A": "1"}); seenHash != want {
		t.Errorf("摘要綁錯了東西：\n got %s\nwant %s", seenHash, want)
	}
}
