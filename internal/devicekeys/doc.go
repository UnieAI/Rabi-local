// Package devicekeys 是「裝置簽核的核准」在 Go 版 daemon 上的實作 ——
// 從 TypeScript 版（runtime/apps/ava-local）逐條移植過來的。
//
// # 這個套件在補哪一個洞
//
// HMAC 那張核准票的金鑰是 app 跟 daemon **共用**的，所以它證明的是「這個核准
// 經過 app 之後沒有被改」，不是「app 本身是誠實的」。任何能在 app 行程裡執行
// 程式碼的人，都可以對任何一台已配對的機器簽出一張合法的票，而使用者不必按
// 任何東西。
//
// 裝置簽的核准（WebAuthn）補的就是這一段：私鑰在使用者手機／筆電的安全元件
// 裡，從來沒有到過我們的伺服器。攻擊者拿到整台 app、整個資料庫，也偽造不出
// 一張核准。
//
// # 那個性質成立的唯一理由
//
// **信任清單不由雲端決定。** 這份清單存在使用者自己的電腦上（Store），而且
// 每一次異動都要由一把已經信任的金鑰簽過，或者在那台電腦上當面確認
// （VerifyEnrollment）。如果雲端能自己把一把公鑰加進來，攻擊者根本不用偽造
// 簽章 —— 註冊一把自己的，然後光明正大地簽，方案等於白做。
//
// 具體到程式碼上是一條規矩：**金鑰只從 Store.Keys() 來，frame 上帶什麼公鑰都
// 不可以讀。** vectors_test.go 的 `雲端在 frame 上自帶公鑰` 與 gate_test.go 的
// `TestGateNeverTrustsKeysFromTheWire` 釘著這一條。
//
// # 讀不得的時候停擺，不要退回 HMAC
//
// 信任清單讀不得（別的帳號寫得了、JSON 被弄壞）＝ 我們判斷不出這台機器該不該
// 只收裝置票。這時候「忽略這個檔案、退回 HMAC」看起來比較友善，但那正是攻擊者
// 要的降級 —— 把檔案弄壞就好。所以整台機器的核准停擺（Gate 回
// device_store_unsafe），並且說出原因。
//
// # 跟 TS 版的等價怎麼證明
//
// testdata/vectors.json 是**由 TS 那一側跑出來的**：testdata/gen-vectors.mjs
// 直接 import runtime/packages/ava-local-protocol/src/*.mjs，把 TS 自己那 21 條
// 測試的語料重建一次，然後記下 TS 實作的真實判斷。Go 這邊 vectors_test.go 讀
// 同一份檔案，要給出同一個判斷；`node gen-vectors.mjs --verify` 則反過來拿
// 那份檔案再餵 TS 一次。兩邊對著同一組輸入，這才叫差分測試。
//
// # 這個套件刻意不做的事
//
//   - **不算 payloadHash。** 那是 canonical.mjs（canonical JSON + approvalSubject）
//     的事，屬於另一個接縫；Gate 收的是已經算好的字串。
//   - **不驗 HMAC 票。** Gate 只負責「兩種票怎麼分」，HMAC 那條路由呼叫端接
//     （Decision.DelegateHMAC）。
//   - **不做簽章原語。** SignatureVerifier 是個窄介面，預設實作在
//     signature.go，呼叫端可以換成別的（例如 avaproto 的）。
package devicekeys
