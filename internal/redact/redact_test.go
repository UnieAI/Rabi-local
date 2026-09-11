package redact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

// 差分語料：**TS 版是規格**，這個檔由它產生（copilot-v2 的
// runtime/apps/ava-local/test/redact-corpus.gen.ts）。只有兩個實作對同一個輸入
// 吐出同一個輸出，「移植」這件事才算數。
//
// 這一份是**副本**。兩個實作 2026-09-11 分家到兩個 repo 之後就沒有一個檔案是
// 兩邊都讀得到的了，而「各自維護一份規格」遲早會漂。所以規則是：
//
//	· 改遮蔽規則 → 先改 TS 那一支，重跑 gen，把產出的 JSON 覆蓋到這裡。
//	· copilot-v2 那一側有一條測試釘住這份語料的 sha256（redact-corpus.test.ts）。
//	  改了那邊就會紅，紅的訊息會叫人把新的複製過來。
//
// 換句話說：漂移會被抓到，只是抓到的地方在另一個 repo。
const corpusRel = "internal/redact/testdata/redact-corpus.json"

type corpusCase struct {
	Name  string       `json:"name"`
	Input string       `json:"input"`
	Text  string       `json:"text"`
	Found map[Kind]int `json:"found"`
}

type corpusStream struct {
	Name   string       `json:"name"`
	Carry  int          `json:"carry"`
	Chunks []string     `json:"chunks"`
	Text   string       `json:"text"`
	Found  map[Kind]int `json:"found"`
}

type corpus struct {
	Note    string         `json:"note"`
	Cases   []corpusCase   `json:"cases"`
	Streams []corpusStream `json:"streams"`
}

// repoRoot 由這個原始檔的位置往上推（internal/redact → repo 根）。
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("拿不到測試檔自己的路徑")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	path := filepath.Join(repoRoot(t), filepath.FromSlash(corpusRel))
	raw, err := os.ReadFile(path)
	if err != nil {
		// 這裡故意 Fatal 而不是 Skip：語料不見就等於差分測試沒在跑，
		// 而「測試變綠但其實沒測」是這個專案踩過好幾次的釘子。
		t.Fatalf("讀不到差分語料 %s：%v\n（它由 copilot-v2 的 runtime/apps/ava-local/test/redact-corpus.gen.ts 產生）", path, err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("語料不是合法的 JSON：%v", err)
	}
	if len(c.Cases) == 0 || len(c.Streams) == 0 {
		t.Fatal("語料是空的 —— 差分測試等於沒跑")
	}
	return c
}

func sameCounts(t *testing.T, got, want map[Kind]int) bool {
	t.Helper()
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// TestCorpusRedact：一次拿到完整內容的那條路，跟 TS 版逐條等價。
func TestCorpusRedact(t *testing.T) {
	c := loadCorpus(t)
	for _, tc := range c.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := Redact(tc.Input)
			if got.Text != tc.Text {
				t.Errorf("輸出跟 TS 版不一樣\n輸入： %q\nGo：   %q\nTS：   %q", tc.Input, got.Text, tc.Text)
			}
			if !sameCounts(t, got.Found, tc.Found) {
				t.Errorf("蓋掉的統計跟 TS 版不一樣\nGo： %v\nTS： %v", got.Found, tc.Found)
			}
		})
	}
}

// TestCorpusStream：一塊一塊來的那條路，跟 TS 版逐條等價（含切法）。
func TestCorpusStream(t *testing.T) {
	c := loadCorpus(t)
	for _, tc := range c.Streams {
		t.Run(tc.Name, func(t *testing.T) {
			s := NewStreamWithCarry(tc.Carry)
			var b strings.Builder
			for _, ch := range tc.Chunks {
				b.WriteString(s.Push(ch))
			}
			b.WriteString(s.Flush())
			got := b.String()
			if got != tc.Text {
				t.Errorf("串流輸出跟 TS 版不一樣\nGo： %q\nTS： %q", got, tc.Text)
			}
			if !sameCounts(t, s.Found(), tc.Found) {
				t.Errorf("蓋掉的統計跟 TS 版不一樣\nGo： %v\nTS： %v", s.Found(), tc.Found)
			}
		})
	}
}

// 被切成兩半的金鑰。這是串流遮蔽存在的唯一理由，所以除了語料之外自己再釘一次：
// 每一個可能的切點都要蓋得到，不是只有語料裡那一個。
func TestKeySplitAcrossChunks(t *testing.T) {
	const secret = "sk-abcdefghijklmnopqrstuvwxyz1234"
	line := "KEY=" + secret + "\n"
	for i := 1; i < len(line); i++ {
		s := NewStream()
		out := s.Push(line[:i]) + s.Push(line[i:]) + s.Flush()
		if strings.Contains(out, "abcdefghijklmnop") {
			t.Fatalf("切在第 %d 個位元組時金鑰整把送出去了：%q", i, out)
		}
		if !strings.Contains(out, Mask(KindOpenAIKey)) {
			t.Fatalf("切在第 %d 個位元組時沒蓋到：%q", i, out)
		}
	}
}

// 一個字元一個字元餵 —— 最壞的切法。
func TestKeyCharByChar(t *testing.T) {
	const secret = "sk-abcdefghijklmnopqrstuvwxyz1234"
	s := NewStream()
	var b strings.Builder
	for _, ch := range "key=" + secret + "\n" {
		b.WriteString(s.Push(string(ch)))
	}
	b.WriteString(s.Flush())
	if strings.Contains(b.String(), "abcdefghijklmnop") {
		t.Fatalf("被切開的金鑰整把送出去了：%q", b.String())
	}
	if s.Found()[KindOpenAIKey] != 1 {
		t.Fatalf("稽核沒記到：%v", s.Found())
	}
}

// 不 Flush 的話最後一段會整段不見 —— 這一條是在釘「一定要 Flush」這件事，
// 讓下一個人看到不呼叫的後果，而不是在測試裡才發現輸出少了一截。
func TestFlushIsMandatory(t *testing.T) {
	s := NewStream()
	out := s.Push("tail-without-newline")
	if out != "" {
		t.Fatalf("沒有換行的尾巴不該提早送出去：%q", out)
	}
	if got := s.Flush(); got != "tail-without-newline" {
		t.Fatalf("Flush 沒把尾巴吐出來：%q", got)
	}
}

// 串流不會吞字、也不會重排。
func TestStreamPreservesOrder(t *testing.T) {
	s := NewStream()
	var b strings.Builder
	for _, part := range []string{"line one\nline ", "two\nline three\n"} {
		b.WriteString(s.Push(part))
	}
	b.WriteString(s.Flush())
	if got := b.String(); got != "line one\nline two\nline three\n" {
		t.Fatalf("串流把內容弄亂了：%q", got)
	}
}

// 切點落在多位元組字元中間時不可以送出壞掉的 UTF-8。
// 中文輸出踩得到，而且壞掉的時候只是「看起來有亂碼」，不會有人當成 bug 修。
func TestStreamNeverSplitsRune(t *testing.T) {
	input := strings.Repeat("漢字測試", 200) // 沒有換行，一定會走到 carry 那條路
	s := NewStreamWithCarry(64)
	var b strings.Builder
	for i := 0; i < len(input); i += 7 { // 7 不是 3 的倍數，chunk 邊界自己也會切到字元中間
		end := i + 7
		if end > len(input) {
			end = len(input)
		}
		part := s.Push(input[i:end])
		if !utf8.ValidString(part) {
			t.Fatalf("送出去的片段是壞掉的 UTF-8：%q", part)
		}
		b.WriteString(part)
	}
	b.WriteString(s.Flush())
	if got := b.String(); got != input {
		t.Fatalf("中文內容被改掉了（長度 %d，應為 %d）", len(got), len(input))
	}
}

// 正常內容一個字都不動。會默默弄壞正常工作的安全功能最後一定會被關掉。
func TestCleanContentUntouched(t *testing.T) {
	code := strings.Join([]string{
		"const sha = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0';",
		"import { useState } from 'react';",
		"const png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';",
		"SELECT * FROM users WHERE id = 42;",
		"order 1234567890123456", // 過不了 Luhn 的一長串數字是訂單編號
	}, "\n")
	got := Redact(code)
	if got.Text != code {
		t.Fatalf("正常內容被蓋到了 —— agent 會照著壞掉的內容做事\n%q", got.Text)
	}
	if len(got.Found) != 0 {
		t.Fatalf("沒蓋到東西卻記了一筆：%v", got.Found)
	}
}

// PushBytes 是 runner 那邊的入口，行為要跟 Push 一致。
func TestPushBytesMatchesPush(t *testing.T) {
	chunks := [][]byte{[]byte("id AKIAIOSFO"), []byte("DNN7EXAMPLE\n")}
	s := NewStream()
	var b strings.Builder
	for _, c := range chunks {
		b.WriteString(s.PushBytes(c))
	}
	b.WriteString(s.Flush())
	if got := b.String(); got != "id "+Mask(KindAWSKey)+"\n" {
		t.Fatalf("PushBytes 的結果不對：%q", got)
	}
}

// Found 回的是複本 —— 呼叫端改它不該動到串流自己的帳。
func TestFoundIsACopy(t *testing.T) {
	s := NewStream()
	s.Push("AKIAIOSFODNN7EXAMPLE\n")
	got := s.Found()
	got[KindAWSKey] = 99
	if s.Found()[KindAWSKey] != 1 {
		t.Fatal("Found() 把內部的統計交出去了")
	}
}

func BenchmarkRedactCommandOutput(b *testing.B) {
	// 一段像樣的指令輸出：大部分是乾淨的，中間夾一把金鑰。
	text := strings.Repeat("2026-09-11T10:00:00Z INFO  handler done in 12ms path=/api/things\n", 200) +
		"OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz1234\n"
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Redact(text)
	}
}
