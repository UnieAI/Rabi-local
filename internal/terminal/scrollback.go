package terminal

import "sync"

// scrollback 是一個以**位元組**為上限的輸出佇列。
//
// 上限算位元組而不是算段數，因為一段就是 PTY 剛好交出來的東西：可能是一個按鍵
// 的回音，也可能是一整個 cat 的百萬位元組。滿了是從前面丟掉整段，所以重畫可能
// 從一個跳脫序列的中間開始 —— 終端機模擬器自己的捲動緩衝溢位時做的就是這件事，
// xterm.js 會在下一個完整的序列上重新同步。
//
// 它自己上鎖：寫的是泵那個 goroutine，讀的是任何一個來要 replay 的呼叫。
type scrollback struct {
	mu       sync.Mutex
	chunks   [][]byte
	size     int
	maxBytes int
}

func newScrollback(maxBytes int) *scrollback {
	return &scrollback{maxBytes: maxBytes}
}

func (s *scrollback) push(chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chunks = append(s.chunks, chunk)
	s.size += len(chunk)
	// 永遠留著最後一段：一段比上限還大的輸出（cat 一個大檔）不該把緩衝清空，
	// 那會讓重畫看到一片空白，而不是「最近發生的事」。
	for s.size > s.maxBytes && len(s.chunks) > 1 {
		s.size -= len(s.chunks[0])
		s.chunks = s.chunks[1:]
	}
}

// bytes 是留著的全部輸出，接成一塊新的位元組。
func (s *scrollback) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, 0, s.size)
	for _, c := range s.chunks {
		out = append(out, c...)
	}
	return out
}

func (s *scrollback) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chunks = nil
	s.size = 0
}
