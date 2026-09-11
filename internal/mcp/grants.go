// grants.go —— 哪些**本機 MCP server** 准被雲端叫，由使用者自己說了算。
//
// 這是「授權資料夾」（runner.Scope）的同一種東西，只是授權的對象從一個路徑
// 換成一個程式，而且共用同一條規矩：**邊界的內容存在使用者的電腦上，雲端
// 只能引用它，不能定義它。**
//
// 檔案位置：~/.unieai/copilot-desktop/mcp-servers.json（見 DefaultGrantsPath）。
//
// # 為什麼另開一個檔案，不寫進 config.json
//
// config.json 是**程式自己會整份覆寫**的檔案（配對、換 token 都會寫）。
// 只有人該編輯的東西放在那裡面，遲早會被一次 token 輪替洗掉 —— 而症狀是
// 「我的 MCP 昨天還在，今天不見了」，沒有任何錯誤訊息。
//
// # 兩種寫法都收
//
// 我們自己的 `servers` 陣列，以及 Claude Desktop 那個大家已經有一份的
// `mcpServers` 物件。要人把既有的設定重打一遍，實務上等於這個功能沒有人
// 開得起來。
//
//	{
//	  "servers": [
//	    { "id": "slidework", "command": "node", "args": ["/Users/roy/slidework/mcp.js"],
//	      "cwd": "/Users/roy/slidework", "env": { "SLIDEWORK_HOME": "/Users/roy/slidework" },
//	      "readOnlyTools": ["list_decks", "get_slide"] }
//	  ]
//	}
//
// **但只讀這一個檔案。** 不會去讀 claude_desktop_config.json、不會掃
// .mcp.json、不會找專案裡的任何東西 —— 那就變成「程式看到什麼就開什麼」，
// 而使用者從來沒有為那些東西做過「要讓雲端叫得動」這個決定。
//
// # readOnlyTools 為什麼由人列，而且不收萬用字元
//
// 第三方 MCP server 上的 publish_deck 是讀是寫，我們**沒有任何辦法知道**。
// server 自己回報的 annotations.readOnlyHint 是被呼叫的那個程式自己說的，
// 而它正是我們在防的東西。一個萬用字元則等於把這台 server **以後新增的每
// 一個工具**都先批准了，而那些工具在使用者寫下那一行的時候還不存在。
package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/UnieAI/Rabi-local/internal/config"
)

// Grant 是一台被授權的本機 MCP server。
type Grant struct {
	ID          string
	Description string
	// Transport 目前只有 "stdio"：使用者手上那些本來就是 stdio（Claude
	// Desktop / Cursor / Claude Code 的設定檔清一色是 command + args），
	// 而且 stdio 的授權綁得住「是哪一個程式」—— 一個 127.0.0.1 的埠，這台
	// 電腦上任何行程都搶得走，我們從連線上分不出接到的是誰。
	Transport string
	Command   string
	Args      []string
	Cwd       string
	// Env 只有這裡列的變數會**額外**進子行程，其餘走 ChildEnv 的允許清單。
	Env map[string]string
	// ReadOnlyTools 是使用者親手宣告「這幾個工具是唯讀的」。其餘一律要票。
	ReadOnlyTools []string
	Enabled       bool
}

// IsReadOnlyTool 回答：使用者有沒有**親手**說過這台 server 的這個工具是唯讀的。
//
// 這是整個套件裡唯一可以讓一次呼叫免票的判斷，所以它只看授權檔，不看任何
// 來自 server 或雲端的東西。
func (g Grant) IsReadOnlyTool(tool string) bool {
	for _, t := range g.ReadOnlyTools {
		if t == tool {
			return true
		}
	}
	return false
}

// GrantFile 是讀一次授權檔的結果。**永遠回得出東西**：檔案不在、壞掉、某一
// 條寫錯，結果都是「這幾台有授權、那幾條有錯」。理由是這條路上丟錯誤的話，
// 一個少打逗號的 JSON 會讓 mcpList 整個失敗，而使用者看到的是「本機 MCP 壞了」
// 而不是「你第 7 行少一個逗號」。
type GrantFile struct {
	Grants []Grant
	// Errors 是逐條的解析錯誤，**不會讓整份檔案失效** —— 一條寫壞不該連累
	// 其他台。這些字串會一路送回雲端給使用者看。
	Errors []string
	// Present 說檔案在不在。不在不是錯誤，就是還沒有人授權過任何 server。
	Present bool
}

var grantIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// DefaultGrantsPath 是授權檔的預設位置，跟 config.json 放在一起。
func DefaultGrantsPath() string {
	return filepath.Join(config.Dir(), "mcp-servers.json")
}

// LoadGrants 讀授權檔。不丟錯誤 —— 所有問題都在 GrantFile.Errors 裡。
func LoadGrants(file string) GrantFile {
	st, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return GrantFile{Present: false}
		}
		return GrantFile{Present: true, Errors: []string{fmt.Sprintf("%s 讀不到：%v", file, err)}}
	}

	// 誰寫得了這個檔案，誰就能透過雲端在這台電腦上跑任意程式。所以「別的
	// 帳號可寫」直接拒絕整份 —— 這是少數值得讓整個檔案失效的情況。
	if runtime.GOOS != "windows" {
		if mode := st.Mode().Perm(); mode&0o022 != 0 {
			return GrantFile{
				Present: true,
				Errors: []string{fmt.Sprintf(
					"%s 是其他帳號可寫的（權限 %o）—— 請改成 600 之後再試。能寫這個檔案的人就能透過雲端在這台電腦上跑任意程式。",
					file, mode)},
			}
		}
	}

	raw, err := os.ReadFile(file)
	if err != nil {
		return GrantFile{Present: true, Errors: []string{fmt.Sprintf("%s 讀不到：%v", file, err)}}
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return GrantFile{Present: true, Errors: []string{fmt.Sprintf("%s 不是合法的 JSON：%v", file, err)}}
	}
	root, isObj := parsed.(map[string]any)
	if !isObj {
		return GrantFile{Present: true, Errors: []string{fmt.Sprintf("%s 的最外層必須是一個物件", file)}}
	}

	out := GrantFile{Present: true}
	seen := map[string]bool{}
	push := func(g *Grant) {
		if g == nil {
			return
		}
		if seen[g.ID] {
			out.Errors = append(out.Errors, fmt.Sprintf("%s：同一個 id 出現兩次，只留第一個", g.ID))
			return
		}
		seen[g.ID] = true
		out.Grants = append(out.Grants, *g)
	}

	// 我們自己的寫法：servers 陣列。
	if arr, isArr := root["servers"].([]any); isArr {
		for _, entry := range arr {
			r, _ := entry.(map[string]any)
			id := any(nil)
			if r != nil {
				if v, has := r["id"]; has {
					id = v
				} else {
					id = r["name"]
				}
			}
			push(normaliseGrant(id, entry, &out.Errors))
		}
	}
	// Claude Desktop 那個大家已經有一份的寫法：mcpServers 物件。
	if obj, isObj := root["mcpServers"].(map[string]any); isObj {
		// map 的走訪順序在 Go 裡是亂的，而「同一個 id 出現兩次只留第一個」
		// 這種訊息不能每次執行都不一樣 —— 排序過再走。
		for _, id := range sortedKeys(obj) {
			push(normaliseGrant(id, obj[id], &out.Errors))
		}
	}

	if len(out.Grants) == 0 && len(out.Errors) == 0 {
		out.Errors = append(out.Errors, fmt.Sprintf(
			`%s 裡沒有任何 server —— 要嘛是 "servers" 陣列，要嘛是 "mcpServers" 物件`, file))
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// 短清單，用最單純的插入排序就好，省一個 import。
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func normaliseGrant(id any, raw any, errs *[]string) *Grant {
	sid := strings.ToLower(strings.TrimSpace(asString(id)))
	if !grantIDRe.MatchString(sid) {
		*errs = append(*errs, fmt.Sprintf("server id「%v」不合法：只收小寫英數、底線與減號，最長 64 個字", id))
		return nil
	}
	r, isObj := raw.(map[string]any)
	if !isObj {
		*errs = append(*errs, fmt.Sprintf("%s：設定必須是一個物件", sid))
		return nil
	}

	// transport 先只有 stdio。寫了別的就明說不支援 —— 安靜地當成 stdio 去
	// spawn 一個其實是 URL 的東西，錯誤訊息會離真正的原因很遠。
	transport := "stdio"
	if v := asString(r["transport"]); v != "" {
		transport = strings.ToLower(v)
	} else if v := asString(r["type"]); v != "" {
		transport = strings.ToLower(v)
	}
	if transport != "stdio" {
		*errs = append(*errs, fmt.Sprintf("%s：transport「%s」還沒支援，目前只有 stdio", sid, transport))
		return nil
	}

	command := strings.TrimSpace(asString(r["command"]))
	if command == "" {
		*errs = append(*errs, fmt.Sprintf("%s：command 是必要的（要跑哪一個程式）", sid))
		return nil
	}

	g := &Grant{
		ID:          sid,
		Description: asString(r["description"]),
		Transport:   "stdio",
		Command:     command,
		Args:        strArray(r["args"], sid+".args", errs),
		Cwd:         asString(r["cwd"]),
		Env:         strMap(r["env"], sid+".env", errs),
		Enabled:     r["enabled"] != false && r["isEnabled"] != false,
	}
	for _, t := range strArray(r["readOnlyTools"], sid+".readOnlyTools", errs) {
		// 萬用字元是「把還不存在的工具先批准了」，明著拒絕而不是安靜忽略。
		if strings.Contains(t, "*") {
			*errs = append(*errs, fmt.Sprintf("%s.readOnlyTools：不收萬用字元「%s」，請逐個列出工具名字", sid, t))
			continue
		}
		g.ReadOnlyTools = append(g.ReadOnlyTools, t)
	}
	return g
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func strArray(v any, what string, errs *[]string) []string {
	if v == nil {
		return nil
	}
	arr, isArr := v.([]any)
	if !isArr {
		*errs = append(*errs, what+" 必須是字串陣列")
		return nil
	}
	var out []string
	for _, x := range arr {
		if s, isStr := x.(string); isStr && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func strMap(v any, what string, errs *[]string) map[string]string {
	if v == nil {
		return nil
	}
	obj, isObj := v.(map[string]any)
	if !isObj {
		*errs = append(*errs, what+" 必須是字串對字串的物件")
		return nil
	}
	out := map[string]string{}
	for _, k := range sortedKeys(obj) {
		if s, isStr := obj[k].(string); isStr {
			out[k] = s
		} else {
			*errs = append(*errs, fmt.Sprintf("%s.%s 不是字串，跳過", what, k))
		}
	}
	return out
}
