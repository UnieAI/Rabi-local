//go:build linux

package confine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 這一支是整個套件唯一證明「真的關住了」的東西：它**真的跑 bwrap**，
// 然後去看授權資料夾外面的那個檔案有沒有被改到。
//
// 為什麼非有不可：純粹組參數的測試可以全綠，而功能是壞的 —— 參數組得漂漂
// 亮亮，bwrap 根本沒有起來（例如替一個不存在的目錄掛 tmpfs，見
// TestBwrapMaskingMissingDirIsFatal）。而那個壞法的症狀是「每一條指令都失敗」
// 或更糟的「沒有關押但看起來有」。
//
// 這台機器上沒有 bwrap 的時候，下面會**明著**跳過並說出原因（連 stderr 也
// 印一份，因為 go test 不加 -v 是看不到 skip 訊息的）。安靜地跳過等於
// 假裝驗過了。

// requireBwrap 回傳一個真的可用的 bwrap 關押，沒有就大聲跳過。
func requireBwrap(t *testing.T, home string) Confinement {
	t.Helper()
	kind, bin, why := DetectNative()
	if kind != KindBwrap {
		reason := fmt.Sprintf("這台機器上沒有可用的 bwrap，關押的**實際效果**沒有被驗到：%s", why)
		fmt.Fprintf(os.Stderr, "\n[confine] 跳過真的執行的測試 —— %s\n\n", reason)
		t.Skip(reason)
	}
	c, err := NewNative(KindBwrap, NativeOptions{Bin: bin, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// realBase 開一個**不在 /tmp 底下**的測試目錄。
//
// 這件事是有意義的：bwrap 會 --tmpfs /tmp，所以一個放在 /tmp 的「界外檔案」
// 在沙盒裡根本看不見。那樣的話「寫不進去」會因為**錯的理由**而通過 ——
// 我們要驗的是唯讀，不是看不見。
func realBase(t *testing.T) string {
	t.Helper()
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if d, err := os.MkdirTemp(home, ".ava-confine-test-"); err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			return d
		}
	}
	t.Log("家目錄開不了暫存目錄，退回 /tmp —— 界外檔案在沙盒裡會是「看不見」而不是「唯讀」，這一輪驗到的東西比較弱")
	return t.TempDir()
}

// runConfined 把一段 bash 包進關押裡真的執行，回傳合併輸出。
func runConfined(t *testing.T, c Confinement, root, cwd, script string) (string, error) {
	t.Helper()
	cmd, err := c.Wrap([]string{"bash", "-lc", script}, Options{Root: root, Cwd: cwd})
	if err != nil {
		t.Fatalf("包不起來：%v", err)
	}
	bin, args := cmd.Split()
	ex := exec.Command(bin, args...)
	ex.Dir = cmd.Dir
	out, err := ex.CombinedOutput()
	return string(out), err
}

func setupWorkspace(t *testing.T) (root, outside string) {
	t.Helper()
	base := realBase(t)
	root = filepath.Join(base, "root")
	outside = filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, outside
}

func TestBwrapWritesInsideTheGrantedFolder(t *testing.T) {
	home, _ := os.UserHomeDir()
	c := requireBwrap(t, home)
	root, _ := setupWorkspace(t)

	if out, err := runConfined(t, c, root, root, "echo written > inside.txt"); err != nil {
		t.Fatalf("授權資料夾裡竟然寫不進去（那會是個壞掉的產品，不是安全的產品）：%v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(root, "inside.txt"))
	if err != nil || strings.TrimSpace(string(raw)) != "written" {
		t.Fatalf("檔案沒有落在主機的授權資料夾裡：%v / %q", err, string(raw))
	}
}

func TestBwrapCannotWriteOutside(t *testing.T) {
	// 這是整件事的重點。
	home, _ := os.UserHomeDir()
	c := requireBwrap(t, home)
	root, outside := setupWorkspace(t)
	target := filepath.Join(outside, "keep.txt")

	// 先證明那個檔案在沙盒裡**看得見**（也就是說，寫不進去是因為唯讀，
	// 不是因為它根本不在那裡）。
	out, _ := runConfined(t, c, root, root, "cat "+shellQuote(target))
	if !strings.Contains(out, "original") {
		t.Skipf("界外檔案在沙盒裡看不見（%q），這一輪驗不到「唯讀」這件事", strings.TrimSpace(out))
	}

	// 指令的離開碼不重要（shell 對唯讀檔案系統的回報各家不同）；
	// 重要的是**那個檔案沒有被改到**。
	_, _ = runConfined(t, c, root, root, "echo hacked > "+shellQuote(target))
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "original\n" {
		t.Fatalf("授權資料夾外面的檔案被改掉了 —— 關押沒有生效。內容變成 %q", string(raw))
	}
}

func TestBwrapKeepsToolchainReadable(t *testing.T) {
	// 把讀也關掉的話，agent 第一步就失敗：node、python、git、系統函式庫
	// 全都在授權資料夾外面。見套件說明「關的是寫，不是讀」。
	home, _ := os.UserHomeDir()
	c := requireBwrap(t, home)
	root, _ := setupWorkspace(t)

	out, err := runConfined(t, c, root, root, "ls /usr/bin >/dev/null && echo toolchain-ok")
	if err != nil || !strings.Contains(out, "toolchain-ok") {
		t.Fatalf("沙盒裡讀不到系統的 toolchain：%v\n%s", err, out)
	}
}

func TestBwrapHidesSecretDirs(t *testing.T) {
	// 憑證目錄連讀都擋。讀它會失敗，而失敗是看得見的 ——
	// 比「讀到了、被蓋掉了、沒有人知道」好。
	base := realBase(t)
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "id_rsa")
	if err := os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := requireBwrap(t, home)
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	out, _ := runConfined(t, c, root, root, "cat "+shellQuote(key)+" 2>&1; echo ---; ls -A "+shellQuote(filepath.Join(home, ".ssh")))
	if strings.Contains(out, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("私鑰在沙盒裡讀得到 —— 遮蔽沒有生效：\n%s", out)
	}
	// 主機上那把鑰匙當然還在（我們遮的是沙盒裡的視野，不是刪掉使用者的東西）。
	if _, err := os.Stat(key); err != nil {
		t.Fatalf("主機上的私鑰不見了：%v", err)
	}
}

func TestBwrapMaskingMissingDirIsFatal(t *testing.T) {
	// 這一條**故意證明那個坑是真的**：對不存在的路徑掛 tmpfs，整個 bwrap
	// 起不來（bwrap: Can't mkdir …: Read-only file system），於是每一條指令
	// 都死 —— 而純參數測試對這件事一無所知。
	//
	// 沒有這一條的話，BwrapArgs 裡那個 exists 過濾看起來只是個最佳化，
	// 之後很容易被人「順手簡化」掉。
	base := realBase(t)
	home := filepath.Join(base, "emptyhome") // 裡面什麼憑證目錄都沒有
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "root2")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	// 正常的（照實檢查存不存在）：跑得起來。
	ok := requireBwrap(t, home)
	if out, err := runConfined(t, ok, root, root, "echo fine"); err != nil {
		t.Fatalf("憑證目錄不存在時 bwrap 應該照跑：%v\n%s", err, out)
	}

	// 假裝每個憑證目錄都存在：bwrap 必須失敗。失敗才證明那個過濾是有作用的。
	_, bin, _ := DetectNative()
	bad, err := NewNative(KindBwrap, NativeOptions{Bin: bin, Home: home, Exists: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := runConfined(t, bad, root, root, "echo fine")
	if err == nil {
		t.Fatalf("替不存在的目錄掛 tmpfs 竟然成功了 —— 這個平台上那個坑的形狀變了，BwrapArgs 的註解要重寫：\n%s", out)
	}
	if !strings.Contains(out, "mkdir") && !strings.Contains(out, "Read-only") {
		t.Logf("失敗原因跟預期的不同（仍然是失敗）：%s", strings.TrimSpace(out))
	}
}

// shellQuote 把路徑包成 bash 安全的單引號字面值。測試自己要用的小東西 ——
// 正式路徑上的指令是 agent 寫的，不經過這裡。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
