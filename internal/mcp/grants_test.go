package mcp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeGrants(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mcp-servers.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGrantsOurShape(t *testing.T) {
	f := LoadGrants(writeGrants(t, `{
	  "servers": [
	    {
	      "id": "SlideWork",
	      "description": "本機 SlideWork",
	      "command": "node",
	      "args": ["/Users/roy/slidework/mcp.js"],
	      "cwd": "/Users/roy/slidework",
	      "env": { "SLIDEWORK_HOME": "/Users/roy/slidework" },
	      "readOnlyTools": ["list_decks", "get_slide"]
	    },
	    { "id": "paused", "command": "node", "enabled": false }
	  ]
	}`))
	if len(f.Errors) != 0 {
		t.Fatalf("不該有錯誤：%v", f.Errors)
	}
	if len(f.Grants) != 2 {
		t.Fatalf("解出 %d 台", len(f.Grants))
	}
	g := f.Grants[0]
	if g.ID != "slidework" {
		t.Errorf("id 沒有正規化成小寫：%s", g.ID)
	}
	if g.Command != "node" || len(g.Args) != 1 || g.Cwd != "/Users/roy/slidework" || g.Env["SLIDEWORK_HOME"] == "" {
		t.Errorf("欄位不對：%+v", g)
	}
	if !g.IsReadOnlyTool("list_decks") || g.IsReadOnlyTool("publish_deck") {
		t.Errorf("readOnlyTools 判斷不對：%+v", g.ReadOnlyTools)
	}
	if f.Grants[1].Enabled {
		t.Error("enabled:false 還算數")
	}
	// enabled:false 的那一台在 Service 眼裡等於不存在。
	svc := New(Options{Grants: f.Grants})
	if ids := svc.ServerIDs(); len(ids) != 1 || ids[0] != "slidework" {
		t.Errorf("Service 收下了停用的授權：%v", ids)
	}
}

// Claude Desktop 那個大家已經有一份的寫法。不收的話，這個功能上線的那天
// 沒有人有東西可以接。
func TestLoadGrantsClaudeDesktopShape(t *testing.T) {
	f := LoadGrants(writeGrants(t, `{
	  "mcpServers": {
	    "slidework": { "command": "node", "args": ["mcp.js"] },
	    "notes": { "command": "uvx", "args": ["notes-mcp"] }
	  }
	}`))
	if len(f.Errors) != 0 {
		t.Fatalf("不該有錯誤：%v", f.Errors)
	}
	if len(f.Grants) != 2 || f.Grants[0].ID != "notes" || f.Grants[1].ID != "slidework" {
		t.Fatalf("解出來的是 %+v", f.Grants)
	}
}

// 規矩二：授權檔自己的問題要收集起來回報，而且**一條寫壞不連累其他台**。
func TestLoadGrantsCollectsProblems(t *testing.T) {
	f := LoadGrants(writeGrants(t, `{
	  "servers": [
	    { "id": "good", "command": "node", "readOnlyTools": ["a", "get_*"] },
	    { "id": "好名字", "command": "node" },
	    { "id": "nocmd" },
	    { "id": "remote", "transport": "sse", "command": "node" },
	    { "id": "good", "command": "node" },
	    { "id": "badargs", "command": "node", "args": "ls -l", "env": { "A": 1 } }
	  ]
	}`))

	ids := []string{}
	for _, g := range f.Grants {
		ids = append(ids, g.ID)
	}
	if strings.Join(ids, ",") != "good,badargs" {
		t.Fatalf("解出來的是 %v", ids)
	}
	// 壞掉的那台如果有前半段合法的欄位，仍然要留著能用的部分。
	if len(f.Grants[0].ReadOnlyTools) != 1 || f.Grants[0].ReadOnlyTools[0] != "a" {
		t.Fatalf("萬用字元那一條應該被丟掉、其他留著：%+v", f.Grants[0].ReadOnlyTools)
	}

	joined := strings.Join(f.Errors, "\n")
	for _, want := range []string{
		"萬用字元",         // get_* —— 等於把還不存在的工具先批准了
		"不合法",          // 好名字
		"command 是必要的", // nocmd
		"還沒支援",         // transport: sse
		"出現兩次",         // 重複的 good
		"必須是字串陣列",      // args 寫成字串
		"不是字串",         // env.A 是數字
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("錯誤清單裡少了「%s」：\n%s", want, joined)
		}
	}
}

func TestLoadGrantsMissingFileIsNotAnError(t *testing.T) {
	f := LoadGrants(filepath.Join(t.TempDir(), "nope.json"))
	if f.Present || len(f.Errors) != 0 || len(f.Grants) != 0 {
		t.Fatalf("%+v", f)
	}
}

func TestLoadGrantsBrokenJSON(t *testing.T) {
	f := LoadGrants(writeGrants(t, `{ "servers": [ }`))
	if len(f.Errors) != 1 || !strings.Contains(f.Errors[0], "不是合法的 JSON") {
		t.Fatalf("%+v", f.Errors)
	}
}

func TestLoadGrantsEmptyFileSaysSo(t *testing.T) {
	f := LoadGrants(writeGrants(t, `{}`))
	if len(f.Errors) != 1 || !strings.Contains(f.Errors[0], "沒有任何 server") {
		t.Fatalf("%+v", f.Errors)
	}
}

// 能寫這個檔案的人就能透過雲端在這台電腦上跑任意程式 —— 這是少數值得讓
// 整份檔案失效的情況。
func TestLoadGrantsRefusesWorldWritableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的權限模型不是這一套")
	}
	p := writeGrants(t, `{ "servers": [ { "id": "slidework", "command": "node" } ] }`)
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	f := LoadGrants(p)
	if len(f.Grants) != 0 {
		t.Fatal("其他帳號可寫的授權檔還是生效了")
	}
	if len(f.Errors) != 1 || !strings.Contains(f.Errors[0], "600") {
		t.Fatalf("訊息要說得出怎麼修：%+v", f.Errors)
	}
}
