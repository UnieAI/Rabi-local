package terminal

import (
	"strings"
	"testing"
)

func TestScrollbackIsByteBounded(t *testing.T) {
	s := newScrollback(10)
	s.push([]byte("aaaa"))
	s.push([]byte("bbbb"))
	s.push([]byte("cccc")) // 12 > 10 —— 從前面丟掉整段
	if got := string(s.bytes()); got != "bbbbcccc" {
		t.Errorf("應該從前面丟整段，得到 %q", got)
	}

	// 一段就比上限還大（cat 一個大檔）—— 最後一段一定留著，否則重畫是一片空白。
	big := strings.Repeat("x", 50)
	s.push([]byte(big))
	if got := string(s.bytes()); got != big {
		t.Errorf("超大的一段應該自己留下來，得到 %d 個位元組", len(got))
	}

	s.clear()
	if len(s.bytes()) != 0 {
		t.Error("clear 之後應該是空的")
	}
}

func TestClampSize(t *testing.T) {
	cases := []struct{ in, fallback, want int }{
		{0, 24, 24},       // 面板還沒量到
		{-5, 80, 80},      // 拖曳到一半
		{1, 80, 1},        // 合法的最小值
		{10000, 80, 1000}, // 夾住，不是拒絕
		{120, 80, 120},
	}
	for _, c := range cases {
		if got := clampSize(c.in, c.fallback); got != c.want {
			t.Errorf("clampSize(%d, %d) = %d，想要 %d", c.in, c.fallback, got, c.want)
		}
	}
}

func TestTerminalTitle(t *testing.T) {
	cases := []struct {
		env      map[string]string
		hostname string
		want     string
	}{
		{map[string]string{"USER": "roy"}, "roy-mbp.local", "roy@roy-mbp"},
		{map[string]string{"LOGNAME": "roy"}, "box", "roy@box"},
		{map[string]string{"USERNAME": "roy"}, "", "roy"},
		// 被剝乾淨的環境：印 shell，不要印一個 undefined@。
		{map[string]string{}, "box", "shell@box"},
	}
	for _, c := range cases {
		if got := terminalTitle(c.env, c.hostname); got != c.want {
			t.Errorf("terminalTitle(%v, %q) = %q，想要 %q", c.env, c.hostname, got, c.want)
		}
	}
}

func TestChildEnvBlocksSecrets(t *testing.T) {
	in := map[string]string{
		"PATH":                "/usr/bin",
		"HOME":                "/home/roy",
		"LC_ALL":              "zh_TW.UTF-8",
		"OPENAI_API_KEY":      "sk-1",
		"ANTHROPIC_API_TOKEN": "t",
		"SOME_SECRET":         "s",
		"UNIEAI_BASE_URL":     "https://evil",
		"HTTPS_PROXY":         "http://evil",
		"AVA_LOCAL_APP_URL":   "https://evil",
		"RANDOM_THING":        "x", // 不在白名單上：沒有理由讓它過
	}
	out := childEnv(in)
	for _, keep := range []string{"PATH", "HOME", "LC_ALL"} {
		if _, ok := out[keep]; !ok {
			t.Errorf("%s 應該過得去", keep)
		}
	}
	for _, blocked := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_TOKEN", "SOME_SECRET", "UNIEAI_BASE_URL", "HTTPS_PROXY", "AVA_LOCAL_APP_URL", "RANDOM_THING"} {
		if _, ok := out[blocked]; ok {
			t.Errorf("%s 不該漏進子行程", blocked)
		}
	}
}

// TestTerminalEnvFiltersCallerSuppliedEnv —— 雲端塞下來的環境變數也要過白名單。
//
// 這一條是安全性的，不是整潔度的：「可以在別人的 shell 裡種任意環境變數」等於
// 可以改 PATH，等於下一個 npm 不是他的 npm。
func TestTerminalEnvFiltersCallerSuppliedEnv(t *testing.T) {
	out := terminalEnv(
		[]string{"PATH=/usr/bin", "OPENAI_API_KEY=sk-1"},
		map[string]string{"EDITOR": "vim", "NPM_TOKEN": "leak", "SNEAKY_BASE_URL": "https://evil"},
		"/home/roy/work",
	)
	if out["EDITOR"] != "vim" {
		t.Error("白名單上的變數應該收得下")
	}
	if _, ok := out["NPM_TOKEN"]; ok {
		t.Error("呼叫端塞的秘密不該進去")
	}
	if _, ok := out["SNEAKY_BASE_URL"]; ok {
		t.Error("呼叫端塞的 *_BASE_URL 不該進去")
	}
	if out["TERM"] != "xterm-256color" || out["COLORTERM"] != "truecolor" {
		t.Error("TERM/COLORTERM 要最後蓋上去")
	}
	if out["PWD"] != "/home/roy/work" {
		t.Errorf("PWD 要是起始資料夾，得到 %q", out["PWD"])
	}
}
