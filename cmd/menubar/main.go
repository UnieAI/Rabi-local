// Rabi —— 工具列上的那個小東西（macOS 的選單列、Windows 的系統匣、Linux 的
// 狀態列）。
//
//	go build -o Rabi ./cmd/menubar
//	./Rabi
//
// 它**不是** daemon：真正維持連線的是安裝腳本裝下去的
// ~/.unieai/ava-local/bin/ava-local，這支程式只是讀同一個家目錄、畫出來，
// 並且提供開關與換資料夾兩個動作。所以關掉它不會讓這台電腦離線。
package main

import "github.com/UnieAI/Rabi-local/internal/menubar"

func main() { menubar.Run(menubar.Home()) }
