package menubar

import (
	"os/exec"
	"strings"
)

// Linux 沒有一個一定在的選取視窗，所以依序試 zenity 與 kdialog。
//
// 兩個都沒有的時候回空字串 —— 也就是**什麼都不做**。跳一個自己畫的檔案清單
// 出來會比較完整，但那等於在系統匣裡塞進第二套檔案瀏覽器；這個平台上換資料夾
// 的正路仍然是網頁那一邊。
func chooseFolder(start string) string {
	if p, err := exec.LookPath("zenity"); err == nil {
		args := []string{"--file-selection", "--directory", "--title=Which folder may the agent work in?"}
		if start != "" {
			args = append(args, "--filename="+strings.TrimSuffix(start, "/")+"/")
		}
		if out, err := exec.Command(p, args...).Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
		return ""
	}
	if p, err := exec.LookPath("kdialog"); err == nil {
		args := []string{"--getexistingdirectory"}
		if start != "" {
			args = append(args, start)
		}
		if out, err := exec.Command(p, args...).Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}
