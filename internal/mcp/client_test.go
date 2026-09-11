package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// # 這一組測試為什麼要真的起一個行程
//
// stdio 這條路上會出錯的東西全部在**行程邊界**上：起不來、起來了不講話、
// 講到一半死掉、把 log 印在 stdout 上。這些都不是假物件模擬得出來的。
//
// 所以假的 MCP server 就是**測試程式自己**：TestMain 看到那個環境變數就改
// 演 server（Go 測試的標準做法）。不必另外準備一個腳本，也就不必假設使用者
// 的機器上有 node 或 python。

const fakeEnv = "MCP_FAKE_MODE"

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeEnv); mode != "" {
		fakeServerMain(mode)
		return
	}
	os.Exit(m.Run())
}

func fakeServerMain(mode string) {
	switch mode {
	case "exit":
		// 起得來，但馬上就走了（設定錯、缺相依套件的典型樣子）。
		os.Exit(3)
	case "silent":
		// 起得來，但一句話都不回。睡得比測試久就夠了 —— 睡太久的話，測試
		// 跑完之後還會有一個孤兒行程留在機器上。
		time.Sleep(3 * time.Second)
		return
	}

	// 很多 server 會把 log 印在 stdout 上。解不開的那一行要被丟掉，而不是
	// 把整條連線帶走。
	os.Stdout.WriteString("starting up…\n")

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var msg struct {
			ID     *int64 `json:"id"`
			Method string `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) != nil || msg.ID == nil {
			continue // 通知（notifications/initialized）不用回
		}
		var result any
		switch msg.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "serverInfo": map[string]any{"name": "fake"}}
		case "tools/list":
			result = map[string]any{"tools": []any{
				map[string]any{"name": "list_decks", "description": "列出簡報"},
				map[string]any{"name": "publish_deck", "annotations": map[string]any{"readOnlyHint": true}},
			}}
		case "tools/call":
			result = map[string]any{
				"content": []any{map[string]any{"type": "text", "text": "called " + msg.Params.Name +
					" with " + msg.Params.Arguments["deck"].(string)}},
				"isError": false,
			}
		default:
			result = map[string]any{}
		}
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": *msg.ID, "result": result})
		os.Stdout.Write(append(out, '\n'))
	}
}

func fakeGrant(t *testing.T, mode string, readOnly ...string) Grant {
	t.Helper()
	return Grant{
		ID:            "fake",
		Transport:     "stdio",
		Command:       os.Args[0], // 測試程式自己
		Env:           map[string]string{fakeEnv: mode},
		ReadOnlyTools: readOnly,
		Enabled:       true,
	}
}

func TestStdioRoundTrip(t *testing.T) {
	svc := New(Options{Grants: []Grant{fakeGrant(t, "ok", "list_decks")}, RequestTimeout: 10 * time.Second})
	defer svc.CloseAll()
	ctx := context.Background()

	listings := svc.List(ctx, "")
	if len(listings) != 1 {
		t.Fatalf("%+v", listings)
	}
	l := listings[0]
	if l.Error != nil {
		t.Fatalf("問工具清單失敗：%s", *l.Error)
	}
	if len(l.Tools) != 2 || l.Tools[0].Name != "list_decks" {
		t.Fatalf("工具清單不對：%+v", l.Tools)
	}
	// server 原樣回報的欄位要留著（雲端要顯示，人也要看得到它自稱唯讀）。
	if l.Tools[0].Raw["description"] != "列出簡報" {
		t.Errorf("description 掉了：%+v", l.Tools[0].Raw)
	}
	if _, hasHint := l.Tools[1].Raw["annotations"]; !hasHint {
		t.Errorf("annotations 掉了：%+v", l.Tools[1].Raw)
	}

	out, err := svc.Call(ctx, "fake", "publish_deck", map[string]any{"deck": "q3"}, 10*time.Second)
	if err != nil {
		t.Fatalf("呼叫失敗：%v", err)
	}
	text := out.Content.([]any)[0].(map[string]any)["text"]
	if text != "called publish_deck with q3" {
		t.Fatalf("回來的是 %v", text)
	}

	// 第二次呼叫走的是同一條連線（懶啟動、用完留著）。
	if _, err := svc.Call(ctx, "fake", "list_decks", map[string]any{"deck": "q4"}, 10*time.Second); err != nil {
		t.Fatalf("第二次呼叫失敗：%v", err)
	}
}

// 起不來是最常見的一種失敗（打錯路徑、那個程式沒裝）。錯誤訊息要說得出
// **是哪一台**、**真正的系統錯誤是什麼** —— 使用者要靠這一句去改授權檔。
func TestSpawnFailureSaysWhichServerAndWhy(t *testing.T) {
	grant := Grant{ID: "slidework", Transport: "stdio", Command: "/definitely/not/a/real/program", Enabled: true}
	svc := New(Options{Grants: []Grant{grant}, RequestTimeout: 2 * time.Second})
	defer svc.CloseAll()

	listings := svc.List(context.Background(), "")
	if listings[0].Error == nil {
		t.Fatal("起不來的 server 卻沒有回報錯誤")
	}
	msg := *listings[0].Error
	if !strings.Contains(msg, "slidework") || !strings.Contains(msg, "起不來") {
		t.Errorf("訊息說不出是哪一台、為什麼：%s", msg)
	}
	// **一台起不來不該讓整份清單失敗** —— 這裡只有一台，所以改看 list 本身
	// 仍然有回東西（而不是丟出錯誤）。
	if listings[0].ID != "slidework" || listings[0].Tools == nil {
		t.Errorf("清單的其他欄位不該一起壞掉：%+v", listings[0])
	}

	_, err := svc.Call(context.Background(), "slidework", "anything", nil, time.Second)
	e, isOurs := err.(*Error)
	if !isOurs || e.Code != "mcp_spawn_failed" {
		t.Fatalf("錯誤碼不對：%#v", err)
	}
}

// 起得來但一句話都不回 —— 這時候沒有計時器的話，雲端那一次呼叫會一路卡到
// relay 的上限，而使用者看到的是「agent 沒反應」。
func TestSilentServerTimesOut(t *testing.T) {
	svc := New(Options{Grants: []Grant{fakeGrant(t, "silent")}, RequestTimeout: 250 * time.Millisecond})
	defer svc.CloseAll()

	_, err := svc.Call(context.Background(), "fake", "anything", nil, 250*time.Millisecond)
	e, isOurs := err.(*Error)
	if !isOurs || e.Code != "mcp_timeout" {
		t.Fatalf("錯誤碼不對：%#v", err)
	}
	if !strings.Contains(e.Message, "fake") || !strings.Contains(e.Message, "initialize") {
		t.Errorf("訊息說不出是哪一台、卡在哪一步：%s", e.Message)
	}
}

// 起得來、但馬上就死掉（缺相依套件的典型樣子）。
func TestServerThatExitsImmediately(t *testing.T) {
	svc := New(Options{Grants: []Grant{fakeGrant(t, "exit")}, RequestTimeout: 3 * time.Second})
	defer svc.CloseAll()

	_, err := svc.Call(context.Background(), "fake", "anything", nil, time.Second)
	e, isOurs := err.(*Error)
	if !isOurs {
		t.Fatalf("%#v", err)
	}
	if e.Code != "mcp_server_exited" && e.Code != "mcp_not_running" {
		t.Fatalf("錯誤碼不對：%s（%s）", e.Code, e.Message)
	}
	if !strings.Contains(e.Message, "fake") {
		t.Errorf("訊息說不出是哪一台：%s", e.Message)
	}
}

// 起不來的時候**不留下半個狀態**：使用者把 server 修好之後，下一次呼叫要能
// 重試，而不是得重開整個程式。
func TestRetriesAfterAFailedStart(t *testing.T) {
	c := newStdioConn(fakeGrant(t, "exit"), nil, time.Second)
	defer c.Close("測試結束")
	ctx := context.Background()

	if _, err := c.ListTools(ctx); err == nil {
		t.Fatal("第一次該失敗")
	}
	if c.alive() {
		t.Fatal("起不來卻還留著一條「活著」的連線")
	}
	// 換成一台好的 server（等於使用者把問題修好了），同一個物件要能再起來。
	c.grant = fakeGrant(t, "ok")
	if _, err := c.ListTools(ctx); err != nil {
		t.Fatalf("修好之後還是起不來：%v", err)
	}
}
