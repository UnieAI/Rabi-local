// Package runner 執行雲端送下來的指令與檔案操作。
//
// 這個檔案只做一件事，而它是整個程式裡最不能出錯的一件：**判斷一個路徑是不是
// 真的落在使用者授權過的資料夾裡面。**
//
// 這一道關卡在本機，不在伺服器上。伺服器那側也接了 root（見 cube/relay.mjs 的
// joinRoot），但那是**方便**，不是**保護** —— 伺服器被打穿的話，它送下來的路徑
// 就是攻擊者說了算。使用者的機器上這一關過不了，才是真的過不了。
package runner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrOutsideScope 是唯一該回給雲端的越界錯誤。刻意不帶被拒絕的路徑細節之外的
// 東西 —— 這個訊息會被送回伺服器，不該順便洩漏本機的目錄結構。
var ErrOutsideScope = errors.New("path is outside the authorised folder")

// Scope 是使用者批准過的一組根目錄。
type Scope struct {
	roots []string // 都是已經 EvalSymlinks 過的絕對路徑
}

// NewScope 建立一組授權範圍。傳進來的每個根目錄都會被解析成真實路徑 ——
// **授權目錄本身是 symlink 的情況必須先處理掉**，否則之後每一個合法路徑
// 都會被判成越界（比對的一邊是解析過的、另一邊不是）。
func NewScope(roots []string) (*Scope, error) {
	s := &Scope{}
	for _, r := range roots {
		if strings.TrimSpace(r) == "" {
			continue
		}
		abs, err := filepath.Abs(r)
		if err != nil {
			return nil, err
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			// 根目錄不存在就跳過，不要讓整組授權失效 —— 使用者可能刪掉了
			// 其中一個資料夾，那不該讓另外兩個也不能用。
			continue
		}
		s.roots = append(s.roots, filepath.Clean(real))
	}
	return s, nil
}

// Roots 回傳目前生效的根目錄（已解析）。給工具列顯示用。
func (s *Scope) Roots() []string {
	out := make([]string, len(s.roots))
	copy(out, s.roots)
	return out
}

// Empty 表示還沒有任何授權 —— 這時候所有操作都該被拒絕，而不是預設放行。
func (s *Scope) Empty() bool { return len(s.roots) == 0 }

// Resolve 檢查 p 是否落在授權範圍內，並回傳它的絕對路徑。
//
// 難的地方是**還不存在的路徑**：每一次建檔、建目錄都是這種，所以不能直接對 p
// 做 EvalSymlinks（它會失敗）。做法是從 p 往上找到第一個「真的存在」的祖先，
// 把那個解析開來比對；剩下那段既然不存在，就不可能藏著 symlink 把人帶出去。
//
// 回傳的是**未解析**的絕對路徑，因為呼叫端要用它去建檔；解析過的版本只用於比對。
func (s *Scope) Resolve(p string) (string, error) {
	if s.Empty() {
		return "", ErrOutsideScope
	}
	if !filepath.IsAbs(p) {
		return "", ErrOutsideScope
	}
	clean := filepath.Clean(p)

	// 從自己往上找到第一個存在的祖先。
	probe := clean
	for {
		if _, err := os.Lstat(probe); err == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			// 一路到根都不存在 —— 不可能落在任何授權目錄裡。
			return "", ErrOutsideScope
		}
		probe = parent
	}

	realProbe, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return "", ErrOutsideScope
	}
	realProbe = filepath.Clean(realProbe)

	// 把「不存在的那一段」接回解析過的祖先上，得到 p 真正會落在哪裡。
	tail := strings.TrimPrefix(clean, probe)
	realTarget := filepath.Clean(filepath.Join(realProbe, tail))

	for _, root := range s.roots {
		if realTarget == root || strings.HasPrefix(realTarget, root+string(filepath.Separator)) {
			return clean, nil
		}
	}
	return "", ErrOutsideScope
}

// Covers 回報某個根目錄是否已經在授權範圍內（含被更上層的根目錄涵蓋的情況）。
// 網頁要求一個新根目錄時用這個判斷「要不要問使用者」。
func (s *Scope) Covers(root string) bool {
	if _, err := s.Resolve(root); err != nil {
		return false
	}
	return true
}
