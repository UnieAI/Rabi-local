package host

// doc.go —— 這一層目前**還沒有做到**的事，以及做到它們需要別人補什麼。
//
// 寫在程式碼裡而不是某一封訊息裡，理由跟這個專案其他地方一樣：一個沒有寫下來
// 的缺口，下一個人只會從症狀去猜，而症狀往往指著錯的人。
//
// # 一、比 TS 版嚴的地方（刻意的，不是漏做）
//
//   - **每一條 exec 都要核准票。** TS 版用 classifyCommand（shell-policy.mjs）
//     讓唯讀的指令自動跑、把災難性的指令直接拒絕。Go 這一側還沒有那份分級規則，
//     所以這裡一律要票。方向是對的：少了分級只會讓使用者多按幾次允許，而反過來
//     （沒有分級就自動放行）等於把 `rm -rf ~` 跟 `ls` 當成同一件事。
//     **要補的是 internal/shellpolicy**（classifyCommand 的 Go 版），接進 exec.go
//     的 requireApproval 之前，並且把 verdict == "denied" 做成不問直接拒絕。
//
//   - **app 簽的 HMAC 票一律不收。** 見 approval.go 的 DeviceGate：那把共用金鑰
//     Go 這一版從來沒有拿到過（config/adopt.go 刻意沒有搬 legacy 的 hmacKey）。
//     所以現在這台 daemon 只認使用者裝置簽的票，而一台還沒註冊過 passkey 的機器
//     什麼都改不了。**要補的是 HMAC 票的驗證器與那把金鑰的來源**；補上之前，
//     使用者的第一步是 deviceEnroll（那個 op 不看票，見 devices.go）。
//
// # 二、需要別人補的公開介面（這一層繞過去了，但繞得不漂亮）
//
//  1. **runner.ExecRequest 需要一個「完整替換」的環境欄位。**
//     現在 runner 給子行程的是 os.Environ() 的全部，再把 ExecRequest.Env 疊上去
//     （後者贏）。也就是說允許清單（internal/envguard）在這條路上**只蓋得住值，
//     蓋不住「那個變數存在」**：exec.go 的 execEnv 因此把不該給的變數蓋成空字串。
//     值出不去，但那是一個變通，不是那個規則。真正要的是
//     `ExecRequest.FullEnv []string`（或 `ReplaceEnv bool`），讓 envguard.ChildEnv
//     的輸出可以整份指派給 exec.Cmd.Env。
//
//  2. **relay.Client 需要一個送 hello 的辦法。**
//     hello 要在 `ready` 之後、用**當下那張憑證** POST 到
//     /api/machines/relay/hello。Client 手上就有那張憑證，但沒有交出來的介面，
//     所以 main.go 的 sayHello 另外換了一張。多一次往返（只在每次連上時一次），
//     而且兩張憑證之間有一個很小的窗。建議 `Client.OnReady func() any`：回傳的
//     東西就是 hello 的 body，由 Client 用自己的憑證送出去。
//
//  3. **runner 的 shellFor 沒有匯出。**
//     關押那一層要的是一份已經定案的 argv，所以 exec.go 自己挑 shell
//     （shellArgv），而 runner 內部那一份在這條路上用不到了 —— 兩份「這台機器
//     用什麼跑 bash」遲早會分岔。建議把它匯出成 `runner.ShellArgv(kind, command)`，
//     這裡就改用它。
//
//  4. **terminal 與 mcp 各自還有一份 canonical JSON。**
//     internal/canonical 已經是那份規則的單一來源了（subject.go 用的是它），但
//     terminal/approval.go 與 mcp/subject.go 仍然各有一份拷貝。改規則要三邊一起
//     改，而漏掉的那一次沒有任何症狀，直到某個人的機器名字裡有中文。
//
// # 三、還沒接的東西
//
//   - **config.Takeover / AdoptLegacy 沒有接。** 同一台電腦上還跑著 TypeScript 版
//     Rabi Local 的時候，兩個實作會搶同一張憑證、同一條 relay 連線。接管的能力
//     已經在 internal/config 裡了，缺的是 main.go 的一個子命令與一段說明。
//
//   - **稽核鏈沒有人驗。** audit.Verify 指得出鏈在第幾列被動過，但目前沒有任何
//     地方叫它。開機時驗一次、並在 hello 的 posture 裡說出結果，才是那個承諾的
//     完整形狀。
