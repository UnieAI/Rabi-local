package mcp

import "testing"

func tool(name string) ToolDescriptor {
	return ToolDescriptor{Name: name, Raw: map[string]any{"name": name}}
}

// 這一組盯的是「拆名字」這件事。從第一個 `__` 亂切的版本會在**某些使用者**
// 身上安靜地切錯 —— server id 和工具名字兩邊都可以有底線，所以字串上有歧義。
func TestSplitToolName(t *testing.T) {
	servers := []ServerListing{
		{ID: "my", Tools: []ToolDescriptor{tool("list")}},
		{ID: "my_tools", Tools: []ToolDescriptor{tool("list_decks")}},
		{ID: "slidework", Tools: []ToolDescriptor{tool("publish_deck")}},
	}

	t.Run("server id 含底線，而且左邊那一台是誘餌", func(t *testing.T) {
		// 從第一個 `__` 切會得到 server「my」、工具「tools__list_decks」。
		s, tl, found := SplitToolName("my_tools__list_decks", servers)
		if !found || s != "my_tools" || tl != "list_decks" {
			t.Fatalf("拆成了 %q/%q（found=%v）", s, tl, found)
		}
	})

	t.Run("工具名字含底線", func(t *testing.T) {
		s, tl, found := SplitToolName("slidework__publish_deck", servers)
		if !found || s != "slidework" || tl != "publish_deck" {
			t.Fatalf("拆成了 %q/%q（found=%v）", s, tl, found)
		}
	})

	t.Run("清單上還沒有那個工具時退回前綴比對", func(t *testing.T) {
		// server 剛新增一個工具、而手上的名單是舊的。這時候該讓它真的打到
		// 那台 server 去被拒絕，不是在這裡變成「沒有這個工具」。
		s, tl, found := SplitToolName("slidework__brand_new", servers)
		if !found || s != "slidework" || tl != "brand_new" {
			t.Fatalf("拆成了 %q/%q（found=%v）", s, tl, found)
		}
	})

	t.Run("沒有一台對得上就是拆不出來", func(t *testing.T) {
		if _, _, found := SplitToolName("someoneelse__thing", servers); found {
			t.Fatal("不該拆得出來")
		}
	})

	t.Run("組回去跟拆出來是同一個名字", func(t *testing.T) {
		name := ComposeToolName("my_tools", "list_decks")
		if name != "my_tools__list_decks" {
			t.Fatalf("組出來是 %q", name)
		}
	})
}
