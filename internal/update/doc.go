// Package update 是這個程式的自動更新：把自己換掉，而且只換得成我們簽過的那一份。
//
// 它是 runtime/apps/ava-local/src/{release-verify,update}.ts 的 Go 版第二實作，
// **格式完全相同** —— 同一把公鑰、同一串 token、同一個 `/api/machines/ava-local`
// 端點，所以同一份 latest.manifest 同時餵得動 TS daemon 與這一版。
// testdata 裡的 manifest 就是 TS 那一側真的簽出來的（testdata/gen-manifests.ts）。
//
// # 為什麼要簽章
//
// 自動更新是把一個檔案裝到使用者電腦上並且讓它常駐。如果更新的內容由「雲端
// 說了算」，那 app 被打下來一次＝每一台連上來的電腦都被植入一個永久的後門。
// 所以 daemon 只裝**私鑰簽過**的東西；雲端只負責轉發，它自己造不出來。
//
// # 一份 manifest 是一個簽過名的字串
//
//	avarel.<base64url(payload JSON)>.<base64url(Ed25519 簽章)>
//
// payload 裡同時放版本、發布時間、**changelog**、以及每個平台的檔名／大小／
// sha256。三件事因此被同一個簽章綁在一起：版本號不能被單獨改、changelog
// 不能被單獨竄改（使用者是看著那段字按下更新的）、位元組不能被掉包
// （簽章蓋住 sha256，sha256 蓋住檔案內容）。
//
// 只用 Go 標準函式庫的 crypto/ed25519，**沒有 cgo** —— 三平台交叉編譯要乾淨。
package update

// —— 怎麼接進 main.go ——————————————————————————————————————————————
//
// 這個套件不自己去碰 main：對外只有幾個有文件的匯出函式，接線由 main.go 統一做。
//
//	up := update.New(update.Deps{
//	        Server:         cfg.Server,
//	        CurrentVersion: relay.Version,
//	        Home:           config.Dir(),
//	        // 手邊還有事在做嗎 —— **這個一定要接**，不然更新會打斷正在跑的指令。
//	        IsBusy:      func() bool { return r.Running() > 0 },
//	        // 換檔之前先把自己安靜下來（停掉 relay）。
//	        Quiesce:     func() error { stop(); return nil },
//	        RestartArgs: nil, // 這個程式不帶參數就是啟動 daemon
//	})
//
// relay 收到下行訊息時先問它一句（三個 op：updateCheck / updateStatus /
// updateApply，跟檔案／指令那一組刻意分開：不碰授權資料夾、不需要核准票，
// 而且其中一個會把這個行程換掉）：
//
//	if out, handled := up.HandleOp(ctx, m.Op, args); handled {
//	        ok := out.OK
//	        send(relay.Up{T: "result", ID: m.ID, OK: &ok, Value: out.Output})
//	        return
//	}
//
// 另外兩個進入點：update.ReadOutcome(config.Dir()) 說得出「上一次換版發生了
// 什麼」（開機時印出來，換版成功的那個行程已經不在了，只有它知道）；
// Updater.PerformUpdate 給 CLI 用（同步跑完整條路，不透過 relay）。
//
// # main.go 這一側欠一件事
//
// 冒煙測試會拿**新下載的執行檔**跑一次 `version`，它必須在 stdout 印出乾淨的
// 版本號（例如 0.2.0）並以 0 結束 —— 那是「換過去起得來嗎」最便宜的一道檢查。
// 現在的 main.go 還沒有這個子命令，所以在補上它之前，自動更新會一律停在
// 「新的執行檔說它是…」而不會換檔（安全的那一邊）。要用別的參數的話換
// Deps.VersionArgs。
