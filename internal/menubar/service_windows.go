package menubar

// Windows 上沒有「開機自啟」這種東西可以問 —— TS 那一支的 service.ts 在這個
// 平台回的就是 kind: "none"。所以開關一律走行程本身（`ava-local stop` 與
// 直接起一個 run），而那正是 Actions 在沒有服務時的行為。
//
// **不要為了對稱而假裝有。** 回 true 會讓 Pause 去叫一個不存在的服務，
// 然後安靜地什麼都沒發生。
func serviceInstalled() bool { return false }
func serviceStop() error     { return nil }
func serviceStart() error    { return nil }
