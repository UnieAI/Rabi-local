// names.go —— 引擎看到的那一個工具名字，跟「哪一台 server 的哪一個工具」
// 之間的換算。
//
// 引擎只認得「一台 MCP server」，所以雲端那一端把這台電腦當成一台 server，
// 上面所有本機 server 的工具用 `<server>__<tool>` 攤平成一份清單
// （lib/machines/machine-mcp.ts 的 composeMcpToolName）。
package mcp

import "strings"

// ComposeToolName 是引擎看到的那一個名字。
func ComposeToolName(server, tool string) string { return server + "__" + tool }

// SplitToolName 把引擎送來的名字拆回「哪一台 server、哪一個工具」。
//
// **一定要拿真正的清單來比對，不能從第一個 `__` 切**：server id 允許底線
// （my_tools），工具名字也允許（list_decks），所以字串上是有歧義的
// ——「my_tools__list_decks」從左邊切會得到 server「my」、工具
// 「tools__list_decks」。猜錯的症狀是「找不到這個工具」，而使用者看到的是
// agent 說他的 MCP 壞了。
//
// 清單上找不到對應工具時退回「前綴對得上就算」：一台 server 剛新增一個工具、
// 而手上的名單是舊的，這種情況該讓它真的打到那台 server 去被拒絕（錯誤訊息
// 說得出真正的原因），不是在這裡變成一句「沒有這個工具」。
func SplitToolName(name string, servers []ServerListing) (server, tool string, ok bool) {
	for _, s := range servers {
		prefix := s.ID + "__"
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		candidate := name[len(prefix):]
		for _, t := range s.Tools {
			if t.Name == candidate {
				return s.ID, candidate, true
			}
		}
	}
	for _, s := range servers {
		prefix := s.ID + "__"
		if strings.HasPrefix(name, prefix) {
			return s.ID, name[len(prefix):], true
		}
	}
	return "", "", false
}
