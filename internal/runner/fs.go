package runner

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
)

// FSResult 是一次檔案操作的答案。value 會被原樣放進回給雲端的 JSON。
type FSResult struct {
	Value any
	Err   error
}

// FSRequest 是雲端送下來的一次檔案操作。
type FSRequest struct {
	Op      string `json:"op"`
	Path    string `json:"path"`
	Content string `json:"content"` // base64
}

type statOut struct {
	Path        string  `json:"path"`
	Size        int64   `json:"size"`
	MtimeMs     float64 `json:"mtimeMs"`
	IsFile      bool    `json:"isFile"`
	IsDirectory bool    `json:"isDirectory"`
}

type listItem struct {
	Name        string  `json:"name"`
	Path        string  `json:"path"`
	Size        int64   `json:"size"`
	MtimeMs     float64 `json:"mtimeMs"`
	IsFile      bool    `json:"isFile"`
	IsDirectory bool    `json:"isDirectory"`
}

// DoFS 執行一次檔案操作。每一個路徑都先過 Scope —— 沒有例外，也沒有「內部呼叫
// 可以跳過」的捷徑，因為所有呼叫都來自雲端。
func DoFS(scope *Scope, req FSRequest) FSResult {
	p, err := scope.Resolve(req.Path)
	if err != nil {
		return FSResult{Err: err}
	}

	switch req.Op {
	case "read":
		b, err := os.ReadFile(p)
		if err != nil {
			return FSResult{Err: err}
		}
		return FSResult{Value: base64.StdEncoding.EncodeToString(b)}

	case "write":
		raw, err := base64.StdEncoding.DecodeString(req.Content)
		if err != nil {
			return FSResult{Err: err}
		}
		if err := writeAtomic(p, raw); err != nil {
			return FSResult{Err: err}
		}
		return FSResult{Value: nil}

	case "stat":
		st, err := os.Stat(p)
		if err != nil {
			return FSResult{Err: err}
		}
		return FSResult{Value: statOut{
			Path: p, Size: st.Size(),
			MtimeMs:     float64(st.ModTime().UnixNano()) / 1e6,
			IsFile:      st.Mode().IsRegular(),
			IsDirectory: st.IsDir(),
		}}

	case "list":
		entries, err := os.ReadDir(p)
		if err != nil {
			return FSResult{Err: err}
		}
		items := make([]listItem, 0, len(entries))
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue // 列目錄途中被刪掉的檔案不該讓整次列舉失敗
			}
			items = append(items, listItem{
				Name: e.Name(), Path: filepath.Join(p, e.Name()),
				Size:        info.Size(),
				MtimeMs:     float64(info.ModTime().UnixNano()) / 1e6,
				IsFile:      info.Mode().IsRegular(),
				IsDirectory: e.IsDir(),
			})
		}
		// 排序讓面板的順序穩定 —— 目錄在前，其餘照名字。
		sort.Slice(items, func(i, j int) bool {
			if items[i].IsDirectory != items[j].IsDirectory {
				return items[i].IsDirectory
			}
			return items[i].Name < items[j].Name
		})
		return FSResult{Value: items}

	case "delete":
		if err := os.Remove(p); err != nil {
			return FSResult{Err: err}
		}
		return FSResult{Value: nil}

	case "mkdir":
		if err := os.MkdirAll(p, 0o755); err != nil {
			return FSResult{Err: err}
		}
		return FSResult{Value: nil}
	}

	return FSResult{Err: os.ErrInvalid}
}

// writeAtomic 先寫同目錄的暫存檔，再 rename 蓋過去。
//
// 三個理由，每一個都踩過：
//   - **同目錄**，不是 /tmp —— 跨檔案系統的 rename 不是原子的，會退化成
//     copy+delete，讀者就可能讀到半截。
//   - **rename 而不是直接寫** —— 寫到一半斷線（連線掉、程式被關）時，
//     原本的檔案完全沒被碰過，只留下一個暫存檔。
//   - **保留原檔權限** —— 直接建新檔會套用 umask，一個 0600 的設定檔
//     會被悄悄放寬成 0644。
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	perm := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
	}

	tmp, err := os.CreateTemp(dir, ".uac2-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功之後這個就不存在了，Remove 會失敗但無害

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// 先 fsync 再 rename：不然機器突然斷電時，rename 可能已經生效但內容還在
	// page cache 裡，結果是一個長度正確但內容全是 0 的檔案。
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
