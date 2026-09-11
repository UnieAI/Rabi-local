package host

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/UnieAI/Rabi-local/internal/runner"
)

// contain.go —— 「這個路徑在使用者授權的資料夾裡面嗎」。
//
// 真正的判斷在 runner.Scope（解析 symlink、處理還不存在的路徑），這裡只做它
// 上面那一層**線路的規矩**，而那幾條都是 TS 版 contain.mjs 已經寫下來的：
//
//   - 相對路徑是**相對於授權資料夾**，不是相對於這個行程的工作目錄。
//     （runner.Scope.Resolve 只收絕對路徑，所以這個轉換要在這裡做。少了它，
//     一個 `listFiles { path: "." }` 會被判成越界，而使用者看到的是「我的
//     資料夾不見了」。）
//   - `~` 開頭一律拒絕。它看起來像相對路徑，實際上是家目錄 —— 把它接在 root
//     後面會產生一個叫做 `~` 的資料夾，那既不是使用者的意思，也掩蓋了一次
//     本來該被看見的越界。
//   - 路徑裡有 NUL 就是壞的請求，不是越界。

// pathError 是一次被路徑圍籬擋下來的請求。
//
// 代碼是雲端那一側認得的那一組：outside_root 與 home_relative 都會被翻成契約的
// workspace_escape（cube/relay.mjs 的 ERROR_MAP），換一個字就是那一頭讀不懂。
type pathError struct {
	Code    string
	Message string
}

// resolve 把雲端送下來的路徑變成這台電腦上的絕對路徑，並且確認它落在使用者
// 授權過的資料夾裡面。
//
// **沒有 Scope 就是全部拒絕**，不是全部放行：一台還沒有人授權任何資料夾的機器，
// 正確的答案是什麼都不做。
func (h *Host) resolve(requested string) (string, *pathError) {
	if strings.ContainsRune(requested, 0) {
		return "", &pathError{Code: "bad_path", Message: "路徑裡有 NUL。"}
	}
	if requested == "~" || strings.HasPrefix(requested, "~/") || strings.HasPrefix(requested, `~\`) {
		return "", &pathError{Code: "home_relative", Message: "不接受 ~ 開頭的路徑；請給授權資料夾裡的相對路徑或絕對路徑。"}
	}
	if h.scope == nil || h.scope.Empty() {
		return "", &pathError{
			Code:    "outside_root",
			Message: "這台電腦還沒有授權任何資料夾給 agent 使用。",
		}
	}

	abs := requested
	if !filepath.IsAbs(abs) {
		if h.root == "" {
			return "", &pathError{Code: "outside_root", Message: "這台電腦沒有授權資料夾，相對路徑無從解起。"}
		}
		// 空字串當成授權資料夾本身 —— 跟 TS 版 path.resolve(root, "") 一致。
		abs = filepath.Join(h.root, abs)
	}

	resolved, err := h.scope.Resolve(abs)
	if err != nil {
		if errors.Is(err, runner.ErrOutsideScope) {
			// 訊息刻意不帶被拒絕路徑之外的細節 —— 它會被送回伺服器，不該順便
			// 洩漏本機的目錄結構。
			return "", &pathError{
				Code:    "outside_root",
				Message: "這個路徑不在 agent 被授權的資料夾裡。",
			}
		}
		return "", &pathError{Code: "bad_path", Message: err.Error()}
	}
	return resolved, nil
}

// relTo 是一個絕對路徑相對於授權資料夾的樣子，給回給雲端的清單用。
// 算不出來就原樣回去 —— 一個看得懂的絕對路徑，好過一個空字串。
func relTo(root, abs string) string {
	if root == "" {
		return abs
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return abs
	}
	return rel
}
