package devicekeys

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// 差分測試：同一組輸入，Go 與 TS 必須給出同一個判斷。
//
// testdata/vectors.json **不是手寫的期望值** —— 它是 testdata/gen-vectors.mjs
// 直接 import runtime/packages/ava-local-protocol/src/*.mjs、跑 TS 的實作記下來
// 的。手寫的期望值只證明「Go 符合我以為 TS 是怎樣的」，而這一整批規則的價值
// 全在「兩個 daemon 是同一個東西」。
//
// 語料來自 TS 自己那兩支測試（device-approval.test.mjs 9 條、
// device-enrollment.test.mjs 12 條），加上票的格式與寬鬆解碼的邊界 —— 後面
// 那些是 Go 跟 Node 最容易分歧的地方，而分歧的症狀是「同一張票兩個 daemon
// 給不同的拒絕理由」。

type vectorDoc struct {
	Source     map[string]string  `json:"source"`
	TTLMillis  float64            `json:"deviceApprovalTtlMs"`
	Approval   []approvalVector   `json:"approval"`
	Enrollment []enrollmentVector `json:"enrollment"`
	Ticket     []ticketVector     `json:"ticket"`
}

type verdict struct {
	OK           bool    `json:"ok"`
	Reason       string  `json:"reason"`
	InvokeID     string  `json:"invokeId"`
	Op           string  `json:"op"`
	CredentialID string  `json:"credentialId"`
	Label        *string `json:"label"`
}

type approvalVector struct {
	Name      string            `json:"name"`
	ClaimsB64 string            `json:"claimsB64"`
	Assertion Assertion         `json:"assertion"`
	Expect    expectJSON        `json:"expect"`
	Keys      map[string]string `json:"keys"`
	Now       *float64          `json:"now"`
	UseNonces bool              `json:"useNonces"`
	Runs      int               `json:"runs"`
	Result    []verdict         `json:"result"`
}

type expectJSON struct {
	MachineID   string `json:"machineId"`
	Tool        string `json:"tool"`
	PayloadHash string `json:"payloadHash"`
}

type enrollmentVector struct {
	Name         string            `json:"name"`
	Enrollment   string            `json:"enrollment"`
	By           any               `json:"by"`
	MachineID    string            `json:"machineId"`
	Keys         map[string]string `json:"keys"`
	LocalConfirm bool              `json:"localConfirm"`
	Now          *float64          `json:"now"`
	Result       verdict           `json:"result"`
}

type ticketVector struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Result struct {
		IsDeviceTicket bool `json:"isDeviceTicket"`
		Parsed         *struct {
			ClaimsB64 string    `json:"claimsB64"`
			Assertion Assertion `json:"assertion"`
		} `json:"parsed"`
	} `json:"result"`
}

func loadVectors(t *testing.T) vectorDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("讀不到差分語料：%v（跑 node testdata/gen-vectors.mjs 產生）", err)
	}
	var doc vectorDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("語料壞了：%v", err)
	}
	if len(doc.Approval) == 0 || len(doc.Enrollment) == 0 || len(doc.Ticket) == 0 {
		t.Fatal("語料是空的 —— 差分測試會變成什麼都沒測")
	}
	return doc
}

func at(ms *float64) time.Time {
	if ms == nil {
		return time.Time{}
	}
	return time.UnixMilli(int64(*ms))
}

// setNonces 讓差分測試控制重放登記簿的內容（TS 那邊用一個 Set）。
type setNonces struct{ seen map[string]bool }

func (s *setNonces) Seen(id string) bool           { return s.seen[id] }
func (s *setNonces) Remember(id string, _ float64) { s.seen[id] = true }

func TestApprovalMatchesTypeScript(t *testing.T) {
	doc := loadVectors(t)
	if want := float64(ApprovalTTL.Milliseconds()); doc.TTLMillis != want {
		t.Fatalf("TTL 跟 TS 版不一樣：TS %v ms、Go %v ms", doc.TTLMillis, want)
	}
	for _, v := range doc.Approval {
		t.Run(v.Name, func(t *testing.T) {
			var nonces NonceRegistry
			if v.UseNonces {
				nonces = &setNonces{seen: map[string]bool{}}
			}
			runs := v.Runs
			if runs == 0 {
				runs = 1
			}
			for i := 0; i < runs; i++ {
				claims, err := VerifyDeviceApproval(v.ClaimsB64, v.Assertion, Expect{
					MachineID:   v.Expect.MachineID,
					Tool:        v.Expect.Tool,
					PayloadHash: v.Expect.PayloadHash,
				}, ApprovalDeps{Keys: v.Keys, Now: at(v.Now), Nonces: nonces})

				want := v.Result[i]
				switch {
				case want.OK && err != nil:
					t.Fatalf("第 %d 次：TS 放行，Go 拒絕（%s）", i+1, err)
				case !want.OK && err == nil:
					t.Fatalf("第 %d 次：TS 拒絕（%s），Go 放行", i+1, want.Reason)
				case !want.OK && string(err.(Refusal)) != want.Reason:
					t.Fatalf("第 %d 次：理由不一樣 —— TS %q、Go %q", i+1, want.Reason, err)
				case want.OK && claims.InvokeID != want.InvokeID:
					t.Fatalf("第 %d 次：invokeId 不一樣 —— TS %q、Go %q", i+1, want.InvokeID, claims.InvokeID)
				}
			}
		})
	}
}

func TestEnrollmentMatchesTypeScript(t *testing.T) {
	doc := loadVectors(t)
	for _, v := range doc.Enrollment {
		t.Run(v.Name, func(t *testing.T) {
			req, err := VerifyEnrollment(v.Enrollment, AssertionFrom(v.By), EnrollmentDeps{
				MachineID:    v.MachineID,
				Keys:         v.Keys,
				LocalConfirm: v.LocalConfirm,
				Now:          at(v.Now),
			})
			want := v.Result
			switch {
			case want.OK && err != nil:
				t.Fatalf("TS 放行，Go 拒絕（%s）", err)
			case !want.OK && err == nil:
				t.Fatalf("TS 拒絕（%s），Go 放行", want.Reason)
			case !want.OK:
				if got := string(err.(Refusal)); got != want.Reason {
					t.Fatalf("理由不一樣 —— TS %q、Go %q", want.Reason, got)
				}
				return
			}
			if req.Op != want.Op || req.CredentialID != want.CredentialID {
				t.Fatalf("放行的內容不一樣 —— TS %s/%s、Go %s/%s", want.Op, want.CredentialID, req.Op, req.CredentialID)
			}
			wantLabel := ""
			if want.Label != nil {
				wantLabel = *want.Label
			}
			if req.Label != wantLabel {
				t.Fatalf("label 不一樣 —— TS %q、Go %q", wantLabel, req.Label)
			}
		})
	}
}

func TestTicketParsingMatchesTypeScript(t *testing.T) {
	doc := loadVectors(t)
	for _, v := range doc.Ticket {
		t.Run(v.Name, func(t *testing.T) {
			if got := IsDeviceTicket(v.Token); got != v.Result.IsDeviceTicket {
				t.Fatalf("isDeviceTicket 不一樣 —— TS %v、Go %v", v.Result.IsDeviceTicket, got)
			}
			claimsB64, assertion, ok := ParseDeviceTicket(v.Token)
			if (v.Result.Parsed != nil) != ok {
				t.Fatalf("拆不拆得開不一樣 —— TS %v、Go %v", v.Result.Parsed != nil, ok)
			}
			if !ok {
				return
			}
			if claimsB64 != v.Result.Parsed.ClaimsB64 || assertion != v.Result.Parsed.Assertion {
				t.Fatalf("拆出來的東西不一樣 —— TS %+v、Go %+v", *v.Result.Parsed, assertion)
			}
		})
	}
}

// TestVectorsStillMatchTypeScript 是差分的**另一半**：拿同一份已提交的語料
// 再餵 TS 一次。
//
// 只比對 Go 與一份靜態 JSON 的話，TS 那邊改了規則而忘記同步 Go，這裡會安靜地
// 全綠 —— 語料是舊的，Go 符合舊的，沒有人會知道。所以這一條真的去跑 node。
//
// 沒有 node（或這份 checkout 裡沒有 runtime/）就跳過：Go 版 daemon 要能在
// 一台只有 Go 工具鏈的機器上建得起來。
func TestVectorsStillMatchTypeScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("這台機器沒有 node，跳過 TS 那一側")
	}
	gen := filepath.Join("testdata", "gen-vectors.mjs")
	proto := filepath.Join("..", "..", "..", "runtime", "packages", "ava-local-protocol", "src", "device-approval.mjs")
	if _, err := os.Stat(proto); err != nil {
		t.Skipf("這份 checkout 裡沒有 TS 版協定（%v），跳過", err)
	}
	out, err := exec.Command(node, gen, "--verify").CombinedOutput()
	if err != nil {
		t.Fatalf("TS 那一側跟語料對不上：\n%s", out)
	}
	t.Log(string(out))
}
