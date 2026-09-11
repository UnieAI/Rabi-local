// Package mcp 讓雲端的 agent 叫得動**使用者自己電腦上**的 MCP server。
//
// # 為什麼要有這條路
//
// 現在的 MCP server 是「在資料庫裡登記一個網址、由引擎去連」。使用者筆電上
// 跑的那幾台沒有對外的埠 —— 而那不是缺陷，是刻意的：一個為了讓雲端連得到
// 而開在使用者機器上的埠，正是這整套設計在避免的東西。
//
// 所以走這個程式本來就有的那條**外撥**長連線：雲端把「叫哪一台 server 的
// 哪一個工具」當成一個 frame 推下來，daemon 在本機跟那台 server 講話（stdio），
// 把結果送回去。
//
// # 三條不能動的規矩
//
//  1. **雲端只說得出 server 的 id。** 要跑什麼程式、在哪個資料夾、帶哪些環境
//     變數，只從使用者電腦上的授權檔讀（grants.go）。frame 上就算帶了
//     `command`，這裡讀都不讀 —— 少了這一條，「本機 MCP」這個 op 就等於一個
//     沒有分級、沒有遮蔽的 exec。
//
//  2. **每一次會改東西的呼叫都要票。** 唯一的例外是使用者親手在授權檔裡列進
//     `readOnlyTools` 的那幾個工具。MCP 規格裡的 `annotations.readOnlyHint`
//     是**被呼叫的那個程式自己說的**，而它正是這套設計在防的對象，所以那個
//     欄位原樣帶回去給人看，但**永遠不參與**「要不要票」的判斷
//     （host.go 的 HandleCall，以及 host_test.go 裡盯著這件事的那個測試）。
//
//  3. **授權檔自己的問題要講出來。** 打錯字、權限太寬、範圍太大，都收集成
//     grantErrors 一路送回雲端 —— 那是**使用者要修**的東西，而他看不到自己
//     電腦上的 daemon log。
//
// # 對外的進入點
//
// main.go 只要建一個 Host，然後把 mcpList / mcpCall 兩個 op 轉給
// [Host.HandleList] 與 [Host.HandleCall]，收到的 [Result] 形狀跟
// runner.DoFS 一樣（OK / Value / Err），直接放進 relay.Up 即可。
package mcp

import "fmt"

// Error 是這條路上唯一的錯誤型別。**一定帶 code** —— 雲端那端要靠它分辨
// 「這台機器沒授權過這個 server」跟「那台 server 沒回話」，兩者的處置完全
// 不同（一個要請使用者去授權，一個是叫他看看自己的程式）。
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func errf(code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// Result 是一個 op 的答案，形狀跟 runner.DoFS 對齊，方便 main.go 直接轉成
// relay.Up。
type Result struct {
	OK    bool
	Value any
	Err   *Error
}

func ok(value any) Result  { return Result{OK: true, Value: value} }
func fail(e *Error) Result { return Result{OK: false, Err: e} }
func failf(code, format string, a ...any) Result {
	return fail(errf(code, format, a...))
}

// Logger 是這個套件唯一的輸出管道。給 nil 就完全不講話（測試用）。
type Logger func(format string, a ...any)

func (l Logger) printf(format string, a ...any) {
	if l != nil {
		l(format, a...)
	}
}
