package host

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// files_test.go —— 路徑圍籬與檔案 op 的線路形狀。
//
// 圍籬本身（symlink、還不存在的路徑）是 runner.Scope 的測試在守的；這裡守的是
// **圍籬有沒有被接上去**，以及回給雲端的形狀對不對 —— 換一個欄位名就是那一頭
// 讀不到，而畫面上不會有任何錯誤，只會少一列。

// outsideFile / outsideDir 是「絕對而且一定在授權資料夾外面」的路徑。
//
// **不能寫死 /etc/passwd。** 在 Windows 上 filepath.IsAbs("/etc/passwd") 是
// false（那裡的絕對路徑要有磁碟機代號），所以它會被當成相對路徑接到授權資料夾
// 後面 —— 結果是合法的 root\etc\passwd，寫入成功，而這條測試紅在一個其實
// 沒有破洞的地方。2026-09-11 第一次在 Windows 跑 CI 時撞到。
func outsideFile() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/passwd"
}

func outsideDir() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32`
	}
	return "/etc"
}

// 每一個帶路徑的 op 都要過圍籬，沒有例外，也沒有「內部呼叫可以跳過」的捷徑。
func TestEveryPathOpIsFencedIn(t *testing.T) {
	ops := []struct {
		op   string
		args map[string]any
	}{
		{"readFile", map[string]any{"path": outsideFile()}},
		{"writeFile", map[string]any{"path": outsideFile(), "contentBase64": "eA=="}},
		{"statFile", map[string]any{"path": outsideFile()}},
		{"listFiles", map[string]any{"path": outsideDir()}},
		{"deleteFile", map[string]any{"path": outsideFile()}},
		{"ensureDir", map[string]any{"path": filepath.Join(outsideDir(), "evil")}},
		{"exec", map[string]any{"command": "ls", "cwd": outsideDir()}},
	}
	for _, c := range ops {
		t.Run(c.op, func(t *testing.T) {
			h := newHarness(t)
			rec := h.call(c.op, c.args, goodTicket)
			if code := failureCode(t, rec.final(t)); code != "outside_root" {
				t.Fatalf("代碼應該是 outside_root（雲端會把它翻成 workspace_escape），拿到 %q", code)
			}
		})
	}
}

// `~` 看起來像相對路徑，實際上是家目錄。接在授權資料夾後面會產生一個叫做 `~`
// 的資料夾 —— 既不是使用者的意思，也掩蓋了一次本來該被看見的越界。
func TestHomeRelativePathsAreRefusedOutright(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"~", "~/.ssh/id_rsa"} {
		rec := h.call("readFile", map[string]any{"path": p}, "")
		if code := failureCode(t, rec.final(t)); code != "home_relative" {
			t.Fatalf("%q 的代碼應該是 home_relative，拿到 %q", p, code)
		}
	}
}

// 相對路徑是**相對於授權資料夾**，不是相對於這個行程的工作目錄。
func TestRelativePathsResolveAgainstTheGrantedFolder(t *testing.T) {
	h := newHarness(t)
	os.WriteFile(filepath.Join(h.root, "note.txt"), []byte("內容"), 0o600)

	rec := h.call("readFile", map[string]any{"path": "note.txt"}, "")
	raw, _ := base64.StdEncoding.DecodeString(output(t, rec.final(t))["contentBase64"].(string))
	if string(raw) != "內容" {
		t.Fatalf("相對路徑解錯地方了：%q", raw)
	}
}

// 一台還沒有人授權任何資料夾的機器，正確的答案是什麼都不做。
func TestAMachineWithNoGrantedFolderRefusesEverything(t *testing.T) {
	h := New(Options{MachineID: "m-1", Gate: &acceptingGate{}})
	rec := &recorder{}
	h.Dispatch(invoke("readFile", map[string]any{"path": "anything"}), rec.emit)
	if code := failureCode(t, rec.final(t)); code != "outside_root" {
		t.Fatalf("代碼應該是 outside_root，拿到 %q", code)
	}
}

/* ── 回給雲端的形狀 ───────────────────────────────────────────────────── */

// readFile 的內容也要過遮蔽 —— `.env` 正是 agent 為了做別的事而順手讀到的東西，
// 而這條路上只有這裡還在使用者自己的機器上。
func TestReadFileMasksSecretsAndStillReportsTheRealSize(t *testing.T) {
	h := newHarness(t)
	secret := "ghp_" + strings.Repeat("b", 36)
	body := "GITHUB=" + secret + "\n"
	os.WriteFile(filepath.Join(h.root, ".env"), []byte(body), 0o600)

	out := output(t, h.call("readFile", map[string]any{"path": ".env"}, "").final(t))
	raw, _ := base64.StdEncoding.DecodeString(out["contentBase64"].(string))
	if strings.Contains(string(raw), secret) {
		t.Fatalf("金鑰原樣送出去了：%q", raw)
	}
	// size 是**原檔**的大小，不是蓋掉之後的長度：那是檔案的事實，而且呼叫端
	// 會拿它跟 statFile 對帳。
	if out["size"] != len(body) {
		t.Fatalf("size 回的不是原檔大小：%v，應該是 %d", out["size"], len(body))
	}
}

// 目錄不是檔案。這一條看起來多餘，但少了它，readFile 一個資料夾會回一段
// 看不懂的錯誤而不是「這不是一個檔案」。
func TestReadFileOnADirectoryIsNotFoundNotAConfusingError(t *testing.T) {
	h := newHarness(t)
	os.Mkdir(filepath.Join(h.root, "dir"), 0o755)
	rec := h.call("readFile", map[string]any{"path": "dir"}, "")
	if code := failureCode(t, rec.final(t)); code != "not_found" {
		t.Fatalf("代碼應該是 not_found，拿到 %q", code)
	}
}

// **檔案不存在不是錯誤，是 stat: null** —— 呼叫端問的正是「它在不在」，
// 而一個錯誤會讓它分不出「不在」跟「問不到」。
func TestStatOnAMissingFileIsNullNotAnError(t *testing.T) {
	h := newHarness(t)
	out := output(t, h.call("statFile", map[string]any{"path": "沒有這個"}, "").final(t))
	if out["stat"] != nil {
		t.Fatalf("應該是 null，拿到 %v", out["stat"])
	}
}

// 清單裡的 path 是**相對於授權資料夾**的，而且資料夾排在前面。
func TestListFilesReturnsRelativePathsInAStableOrder(t *testing.T) {
	h := newHarness(t)
	os.Mkdir(filepath.Join(h.root, "zz-dir"), 0o755)
	os.WriteFile(filepath.Join(h.root, "aa.txt"), []byte("x"), 0o600)

	entries := output(t, h.call("listFiles", map[string]any{"path": "."}, "").final(t))["entries"].([]statEntry)
	if len(entries) != 2 {
		t.Fatalf("應該列到兩個東西，拿到 %d 個", len(entries))
	}
	if !entries[0].IsDirectory {
		t.Fatal("資料夾應該排在前面 —— 面板的順序要穩定")
	}
	for _, e := range entries {
		if filepath.IsAbs(e.Path) {
			t.Fatalf("path 應該是相對的，拿到 %q", e.Path)
		}
	}
}

// 刪掉授權資料夾本身等於一次點擊清空使用者的整個工作區，外加讓這台機器從此
// 什麼都做不了。它在圍籬裡面，所以圍籬不會擋 —— 這一條要自己擋。
func TestDeletingTheGrantedFolderItselfIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{".", h.root} {
		rec := h.call("deleteFile", map[string]any{"path": p}, goodTicket)
		if code := failureCode(t, rec.final(t)); code != "denied" {
			t.Fatalf("%q 的代碼應該是 denied，拿到 %q", p, code)
		}
		if _, err := os.Stat(h.root); err != nil {
			t.Fatal("授權資料夾被刪掉了")
		}
	}
}

// 刪一個本來就不存在的東西算成功：呼叫端要的是「這個路徑之後不存在」，
// 而那件事已經成立。
func TestDeletingSomethingAlreadyGoneSucceeds(t *testing.T) {
	h := newHarness(t)
	if res := h.call("deleteFile", map[string]any{"path": "從來沒有過"}, goodTicket).final(t); !res.OK {
		t.Fatalf("不該失敗：%+v", res.Output)
	}
}

// 太大的檔案要說「太大」，而不是讓每一層都先把它整份放進記憶體。
func TestAnOversizedFileIsRefusedWithItsOwnCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("這一條只是要一個夠大的檔案，不必在每個平台上都寫一次")
	}
	h := newHarness(t)
	big := filepath.Join(h.root, "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxReadBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	rec := h.call("readFile", map[string]any{"path": "big.bin"}, "")
	if code := failureCode(t, rec.final(t)); code != "payload_too_large" {
		t.Fatalf("代碼應該是 payload_too_large，拿到 %q", code)
	}
}

// writeFile 要寫得出中間還不存在的那幾層 —— 不然 agent 得先自己 ensureDir，
// 而那是一張多出來的核准卡。
func TestWriteFileCreatesMissingParents(t *testing.T) {
	h := newHarness(t)
	args := map[string]any{
		"path":          "deep/er/still/x.txt",
		"contentBase64": base64.StdEncoding.EncodeToString([]byte("ok")),
	}
	if res := h.call("writeFile", args, goodTicket).final(t); !res.OK {
		t.Fatalf("寫不出來：%+v", res.Output)
	}
	if b, err := os.ReadFile(filepath.Join(h.root, "deep/er/still/x.txt")); err != nil || string(b) != "ok" {
		t.Fatalf("%v %q", err, b)
	}
}
