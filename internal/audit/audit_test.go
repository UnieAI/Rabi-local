package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 這條鏈是我們對使用者的承諾之一：「做過什麼在你自己的電腦上留了一份，離線
// 就看得到，不必相信我們那一份」。所以這裡守的不只是「有沒有寫」，是
// **「被動過的時候看不看得出來」** —— 一條驗不出竄改的鏈，跟一個普通的
// log 檔沒有差別，而我們卻拿它當證據。

func openTmp(t *testing.T) (*Log, string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	return l, f
}

func TestAppendChainsAndVerifies(t *testing.T) {
	l, f := openTmp(t)
	for _, c := range []struct {
		op, detail string
		v          Verdict
	}{
		{"exec", "rm -rf build", Run},
		{"writeFile", "/home/roy/a.txt", Run},
		{"mcpCall", "slidework/publish_deck", Auto},
		{"exec", "curl evil.example", Refused},
	} {
		if _, err := l.Append(c.op, c.detail, c.v, "inv-"+c.op); err != nil {
			t.Fatal(err)
		}
	}
	r := Verify(f)
	if !r.OK || r.Length != 4 {
		t.Fatalf("剛寫好的鏈驗不過：%+v", r)
	}
}

func TestTamperIsCaughtAndLocated(t *testing.T) {
	// 「鏈壞了」跟「鏈在第 2 列被動過」是完全不同的兩句話，後者才查得下去。
	l, f := openTmp(t)
	for i := 0; i < 4; i++ {
		l.Append("exec", "cmd", Run, "")
	}
	raw, _ := os.ReadFile(f)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	lines[2] = strings.Replace(lines[2], `"detail":"cmd"`, `"detail":"rm -rf /"`, 1)
	os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	r := Verify(f)
	if r.OK {
		t.Fatal("改掉了一列的內容卻驗得過 —— 那這條鏈不是證據")
	}
	if r.BrokenAt != 2 {
		t.Fatalf("指錯位置：說是第 %d 列", r.BrokenAt)
	}
}

func TestRemovingALineIsCaught(t *testing.T) {
	// 抽掉中間一列是最像「什麼都沒發生」的竄改方式。
	l, f := openTmp(t)
	for i := 0; i < 4; i++ {
		l.Append("exec", "cmd", Run, "")
	}
	raw, _ := os.ReadFile(f)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	kept := append(append([]string{}, lines[:2]...), lines[3:]...)
	os.WriteFile(f, []byte(strings.Join(kept, "\n")+"\n"), 0o600)

	if r := Verify(f); r.OK {
		t.Fatal("抽掉一列驗得過 —— 那就藏得住任何一次動作")
	}
}

func TestReopenContinuesTheSameChain(t *testing.T) {
	// daemon 每次重啟都會重開這個檔。接不上的話，每一次重啟都等於開一條新鏈，
	// 而「這之前發生過什麼」就再也證明不了。
	l, f := openTmp(t)
	l.Append("exec", "first", Run, "")
	first := *l.LastHash()

	l2, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if l2.LastHash() == nil || *l2.LastHash() != first {
		t.Fatal("重開之後沒有接上前一列")
	}
	l2.Append("exec", "second", Run, "")
	if r := Verify(f); !r.OK || r.Length != 2 {
		t.Fatalf("接續之後驗不過：%+v", r)
	}
}

func TestVerifyOnAMissingFileIsNotAFailure(t *testing.T) {
	// 還沒跑過任何東西的機器，鏈是空的 —— 那是「沒有紀錄」不是「紀錄壞了」。
	r := Verify(filepath.Join(t.TempDir(), "nope.jsonl"))
	if !r.OK || r.Length != 0 {
		t.Fatalf("空的鏈被當成壞掉：%+v", r)
	}
}

func TestAppendReportsWriteFailures(t *testing.T) {
	// ADR-0002：寫不進稽核就不發票。吞掉這個錯誤，等於讓一個「做了但沒留下
	// 紀錄」的動作照樣發生 —— 那比沒做成更糟。
	dir := t.TempDir()
	f := filepath.Join(dir, "sub", "audit.jsonl")
	l, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(f), 0o500); err != nil {
		t.Skip("改不了權限，跳過")
	}
	defer os.Chmod(filepath.Dir(f), 0o700)
	if _, err := l.Append("exec", "x", Run, ""); err == nil {
		t.Fatal("寫不進去卻回報成功")
	}
}

func TestActionIdIsOptionalButPartOfTheDigest(t *testing.T) {
	l, f := openTmp(t)
	l.Append("exec", "x", Run, "")        // 沒有 actionId
	l.Append("exec", "x", Run, "inv-abc") // 有
	if r := Verify(f); !r.OK || r.Length != 2 {
		t.Fatalf("兩種都要驗得過：%+v", r)
	}
	raw, _ := os.ReadFile(f)
	if !strings.Contains(string(raw), `"actionId":"inv-abc"`) {
		t.Fatal("actionId 沒寫進去 —— 核准與執行就對不起來了")
	}
	if strings.Count(string(raw), "actionId") != 1 {
		t.Fatal("沒有 actionId 的那一列不該留一個空欄位")
	}
}
