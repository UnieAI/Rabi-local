package hmacapproval

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// 語料是**拿 TS 實作真的跑出來的**（approval.mjs 的 mintApprovalToken +
// verifyApprovalToken），不是照規格自己編。
//
// 重新產生：node /tmp/gen-hmac.mjs（腳本在 commit 訊息裡）
//
// 為什麼拒絕的**理由**也要比對：模型與稽核都照著它分辨下一步。「過期」的下一步
// 是再按一次，「摘要不對」是我們兩邊算錯了東西，「簽章不對」是有人動過。
// 混成一句「票不對」的話，那三種人都會做錯事。

var key = []byte("0123456789abcdef0123456789abcdef")

type vector struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Expect struct {
		MachineID   string `json:"machineId"`
		Tool        string `json:"tool"`
		PayloadHash string `json:"payloadHash"`
		InvokeID    string `json:"invokeId"`
	} `json:"expect"`
	Now    int64   `json:"now"`
	OK     bool    `json:"ok"`
	Reason *string `json:"reason"`
}

func TestMatchesTypeScript(t *testing.T) {
	raw, err := os.ReadFile("testdata_vectors.json")
	if err != nil {
		t.Fatalf("語料讀不到：%v", err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 10 {
		t.Fatalf("語料只有 %d 條 —— 這條測試等於空轉", len(vs))
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			c, err := Verify(key, v.Token, Expect{
				MachineID: v.Expect.MachineID, Tool: v.Expect.Tool,
				PayloadHash: v.Expect.PayloadHash, InvokeID: v.Expect.InvokeID,
			}, nil, time.UnixMilli(v.Now))
			if v.OK {
				if err != nil {
					t.Fatalf("TS 說過、Go 說 %v", err)
				}
				if c == nil || c.Tool != v.Expect.Tool {
					t.Fatalf("過了但 claims 不對：%+v", c)
				}
				return
			}
			if err == nil {
				t.Fatalf("TS 說 %s、Go 放行了", *v.Reason)
			}
			if err.Error() != *v.Reason {
				t.Fatalf("理由分岔：TS %s、Go %s", *v.Reason, err)
			}
		})
	}
}

type memNonces map[string]int64

func (m memNonces) Has(n string, now int64) bool { exp, ok := m[n]; return ok && exp > now }
func (m memNonces) Add(n string, exp, now int64) { m[n] = exp }

func TestReplayIsRefusedTheSecondTime(t *testing.T) {
	// 一次同意只換得到一次執行。少了這一條，一張票在有效期內可以被重放到飽。
	raw, _ := os.ReadFile("testdata_vectors.json")
	var vs []vector
	json.Unmarshal(raw, &vs)
	good := vs[0]

	n := memNonces{}
	at := time.UnixMilli(good.Now)
	want := Expect{MachineID: good.Expect.MachineID, Tool: good.Expect.Tool, PayloadHash: good.Expect.PayloadHash}
	if _, err := Verify(key, good.Token, want, n, at); err != nil {
		t.Fatalf("第一次就被拒：%v", err)
	}
	if _, err := Verify(key, good.Token, want, n, at); err != Replayed {
		t.Fatalf("第二次應該是 replayed，拿到 %v", err)
	}
}

func TestWrongKeyIsBadSignatureNotSomethingElse(t *testing.T) {
	// 換一把金鑰 ≠ 票壞了。說錯的話，維運會去查格式而不是去查金鑰。
	raw, _ := os.ReadFile("testdata_vectors.json")
	var vs []vector
	json.Unmarshal(raw, &vs)
	good := vs[0]
	_, err := Verify([]byte("ffffffffffffffffffffffffffffffff"), good.Token,
		Expect{MachineID: good.Expect.MachineID, Tool: good.Expect.Tool, PayloadHash: good.Expect.PayloadHash},
		nil, time.UnixMilli(good.Now))
	if err != BadSignature {
		t.Fatalf("要說是簽章的問題，拿到 %v", err)
	}
}

func TestSignatureIsCheckedBeforeContents(t *testing.T) {
	// 先比內容再比簽章的話，錯誤訊息就是一個神諭：攻擊者可以一格一格問出
	// 他該偽造什麼。這裡用一張簽章壞掉、而且機器也不對的票 —— 回的必須是
	// 簽章那個理由。
	raw, _ := os.ReadFile("testdata_vectors.json")
	var vs []vector
	json.Unmarshal(raw, &vs)
	tampered := vs[7] // 簽章被改
	_, err := Verify(key, tampered.Token, Expect{MachineID: "完全不同的機器", Tool: "completelyOther", PayloadHash: "x"},
		nil, time.UnixMilli(tampered.Now))
	if err != BadSignature {
		t.Fatalf("先洩漏了內容比對的結果：%v", err)
	}
}
