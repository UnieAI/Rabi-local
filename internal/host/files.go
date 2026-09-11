package host

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/UnieAI/Rabi-local/internal/canonical"
	"github.com/UnieAI/Rabi-local/internal/redact"
	"github.com/UnieAI/Rabi-local/internal/relay"
	"github.com/UnieAI/Rabi-local/internal/runner"
)

// files.go —— 六個檔案 op。
//
// 三件事在這裡是不可協商的：
//
//   - **每一個路徑都先過圍籬**（contain.go），沒有例外、也沒有「內部呼叫可以
//     跳過」的捷徑，因為所有呼叫都來自雲端。
//   - **會改東西的三個要票**（writeFile / deleteFile / ensureDir）。讀的那三個
//     不要 —— 那是使用者按「連接電腦」時就已經表達過的意思。
//   - **讀出來的內容要過遮蔽**。`.env`、`credentials`、`config.json` 正是 agent
//     為了做別的事而順手讀到的東西，而這條路上只有這裡還在使用者自己的機器上。

// MaxReadBytes 是一次 readFile 的上限。跟 TS 版一樣 4 MiB —— 再大就不是「讀一個
// 檔案」而是「把一顆硬碟搬過網路」，而中間每一層都會先把它整份放進記憶體。
const MaxReadBytes = 4 * 1024 * 1024

// statEntry 是一個檔案在線路上的樣子。欄位名跟 TS 版逐字相同（雲端那一側直接
// 讀這幾個），**path 是相對於授權資料夾的**，不是這台電腦上的絕對路徑。
type statEntry struct {
	Name        string  `json:"name,omitempty"`
	Path        string  `json:"path"`
	Size        int64   `json:"size"`
	MtimeMs     float64 `json:"mtimeMs"`
	IsFile      bool    `json:"isFile"`
	IsDirectory bool    `json:"isDirectory"`
}

func entryOf(info os.FileInfo, rel string) statEntry {
	return statEntry{
		Path:        rel,
		Size:        info.Size(),
		MtimeMs:     float64(info.ModTime().UnixNano()) / 1e6,
		IsFile:      info.Mode().IsRegular(),
		IsDirectory: info.IsDir(),
	}
}

// readFile 讀一個檔案。唯讀，不要票。
func (h *Host) readFile(inv relay.Invoke, args map[string]any) relay.Result {
	rel := argString(args, "path")
	p, escape := h.resolve(rel)
	if escape != nil {
		return relay.Fail(inv.ID, escape.Code, escape.Message)
	}
	info, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return relay.Fail(inv.ID, "not_found", "沒有這個檔案")
		}
		return relay.Fail(inv.ID, "read_failed", err.Error())
	}
	if !info.Mode().IsRegular() {
		return relay.Fail(inv.ID, "not_found", "這不是一個檔案")
	}
	if info.Size() > MaxReadBytes {
		return relay.Fail(inv.ID, "payload_too_large",
			fmt.Sprintf("這個檔案有 %d 位元組，上限是 %d", info.Size(), MaxReadBytes))
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return relay.Fail(inv.ID, "not_found", "沒有這個檔案")
		}
		return relay.Fail(inv.ID, "read_failed", err.Error())
	}
	// 檔案內容跟指令的輸出走同一道遮蔽 —— 它接下來會經過 relay → app → 引擎
	// → 模型供應商，而這裡是最後一個還在使用者電腦上的地方。
	r := redact.Redact(string(raw))
	if kinds := kindNames(r.Found); kinds != "" {
		h.audit("redact", "readFile "+rel+": "+kinds, "auto", "")
	}
	return relay.Done(inv.ID, map[string]any{
		"contentBase64": base64.StdEncoding.EncodeToString([]byte(r.Text)),
		// size 是**原檔**的大小，不是蓋掉之後的長度：那是檔案的事實，而且
		// 呼叫端會拿它跟 statFile 對帳。
		"size": len(raw),
	})
}

// writeFile 寫一個檔案。**要票。**
func (h *Host) writeFile(inv relay.Invoke, args map[string]any) relay.Result {
	rel := argString(args, "path")
	p, escape := h.resolve(rel)
	if escape != nil {
		return relay.Fail(inv.ID, escape.Code, escape.Message)
	}
	content, err := base64.StdEncoding.DecodeString(argString(args, "contentBase64"))
	if err != nil {
		return relay.Fail(inv.ID, "bad_request", "contentBase64 不是合法的 base64")
	}

	// 票綁的是 frame 上那個路徑字串與內容的摘要（見 approval.go）。
	actionID, aerr := h.requireApproval("writeFile", canonical.PayloadHash(writeFileSubject(rel, content)), inv.Approval, rel)
	if aerr != nil {
		code, msg := codeOf(aerr)
		return relay.Fail(inv.ID, code, msg)
	}

	// 寫入走 runner.DoFS —— 那裡的 writeAtomic 已經把這件事做對了（同目錄暫存
	// 檔、先 fsync 再 rename、保留原檔權限）。這是使用者自己的電腦上、一份沒有
	// 別的副本的工作，所以「絕不留下半截檔案」在這裡不是潔癖。
	res := runner.DoFS(h.scope, runner.FSRequest{
		Op:      "write",
		Path:    p,
		Content: base64.StdEncoding.EncodeToString(content),
	})
	if res.Err != nil {
		return relay.Fail(inv.ID, "write_failed", res.Err.Error())
	}
	h.audit("writeFile", rel, "run", actionID)
	return relay.Done(inv.ID, map[string]any{"path": rel, "bytes": len(content)})
}

// statFile 問一個檔案的資料。唯讀，不要票。
//
// **檔案不存在不是錯誤，是 stat: null** —— 呼叫端問的正是「它在不在」，而一個
// 錯誤會讓它分不出「不在」跟「問不到」。
func (h *Host) statFile(inv relay.Invoke, args map[string]any) relay.Result {
	rel := argString(args, "path")
	p, escape := h.resolve(rel)
	if escape != nil {
		return relay.Fail(inv.ID, escape.Code, escape.Message)
	}
	info, err := os.Stat(p)
	if err != nil {
		return relay.Done(inv.ID, map[string]any{"stat": nil})
	}
	return relay.Done(inv.ID, map[string]any{"stat": entryOf(info, rel)})
}

// listFiles 列一個資料夾。唯讀，不要票。
func (h *Host) listFiles(inv relay.Invoke, args map[string]any) relay.Result {
	requested := argString(args, "path", ".")
	p, escape := h.resolve(requested)
	if escape != nil {
		return relay.Fail(inv.ID, escape.Code, escape.Message)
	}
	items, err := os.ReadDir(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return relay.Fail(inv.ID, "not_found", err.Error())
		}
		return relay.Fail(inv.ID, "list_failed", err.Error())
	}
	base := relTo(h.root, p)
	entries := make([]statEntry, 0, len(items))
	for _, it := range items {
		info, err := it.Info()
		if err != nil {
			// 列目錄途中被刪掉的檔案不該讓整次列舉失敗。
			continue
		}
		e := entryOf(info, filepath.Join(base, it.Name()))
		e.Name = it.Name()
		entries = append(entries, e)
	}
	// 順序穩定，面板才不會每次重畫都跳動：資料夾在前，其餘照名字。
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDirectory != entries[j].IsDirectory {
			return entries[i].IsDirectory
		}
		return entries[i].Name < entries[j].Name
	})
	return relay.Done(inv.ID, map[string]any{"path": p, "entries": entries})
}

// deleteFile 刪掉一個檔案或整棵資料夾。**要票。**
func (h *Host) deleteFile(inv relay.Invoke, args map[string]any) relay.Result {
	rel := argString(args, "path")
	p, escape := h.resolve(rel)
	if escape != nil {
		return relay.Fail(inv.ID, escape.Code, escape.Message)
	}
	// 授權資料夾**本身**不能刪。它在圍籬裡面，所以圍籬不會擋 —— 而刪掉它等於
	// 一次點擊清空使用者的整個工作區，外加讓這台機器從此什麼都做不了。
	if sameFile(p, h.root) {
		return relay.Fail(inv.ID, "denied", "不會刪掉授權資料夾本身。")
	}
	actionID, aerr := h.requireApproval("deleteFile", canonical.PayloadHash(pathSubject("deleteFile", rel)), inv.Approval, rel)
	if aerr != nil {
		code, msg := codeOf(aerr)
		return relay.Fail(inv.ID, code, msg)
	}
	// 遞迴而且「不存在也算成功」—— 跟 TS 版的 rm(recursive, force) 一致：
	// 呼叫端要的是「這個路徑之後不存在」，而它本來就不存在時那件事已經成立。
	if err := os.RemoveAll(p); err != nil {
		return relay.Fail(inv.ID, "delete_failed", err.Error())
	}
	h.audit("deleteFile", rel, "run", actionID)
	return relay.Done(inv.ID, map[string]any{"path": rel})
}

// ensureDir 建一個資料夾（含中間層）。**要票。**
func (h *Host) ensureDir(inv relay.Invoke, args map[string]any) relay.Result {
	rel := argString(args, "path")
	p, escape := h.resolve(rel)
	if escape != nil {
		return relay.Fail(inv.ID, escape.Code, escape.Message)
	}
	actionID, aerr := h.requireApproval("ensureDir", canonical.PayloadHash(pathSubject("ensureDir", rel)), inv.Approval, rel)
	if aerr != nil {
		code, msg := codeOf(aerr)
		return relay.Fail(inv.ID, code, msg)
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		return relay.Fail(inv.ID, "mkdir_failed", err.Error())
	}
	h.audit("ensureDir", rel, "run", actionID)
	return relay.Done(inv.ID, map[string]any{"path": rel})
}

// sameFile 判斷兩個路徑是不是同一個東西。
//
// 比字串不夠：授權資料夾可能是 symlink，而 `/w` 與 `/w/` 是同一個地方。
func sameFile(a, b string) bool {
	if b == "" {
		return false
	}
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// kindNames 是一次遮蔽蓋掉了哪幾種東西，寫進稽核用。
func kindNames(found map[redact.Kind]int) string {
	if len(found) == 0 {
		return ""
	}
	names := make([]string, 0, len(found))
	for k := range found {
		names = append(names, string(k))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
