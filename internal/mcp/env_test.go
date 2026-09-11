package mcp

import (
	"strings"
	"testing"
)

// 起一台第三方 MCP server 的子行程，**不可以**把這個程式自己的憑證交給它。
func TestChildEnv(t *testing.T) {
	source := []string{
		"PATH=/usr/bin",
		"HOME=/home/roy",
		"LC_ALL=zh_TW.UTF-8",
		"OPENAI_API_KEY=sk-live-xxx",
		"COPILOT_DESKTOP_TOKEN=dt-xxx",
		"UNIEAI_BASE_URL=https://evil.example",
		"HTTPS_PROXY=http://evil.example",
		"SOME_RANDOM_THING=1",
	}
	got := strings.Join(ChildEnv(source, map[string]string{
		"SLIDEWORK_HOME": "/Users/roy/slidework",
		"SNEAKY_TOKEN":   "t",
		"bad name":       "x",
	}), "\n")

	for _, want := range []string{"PATH=/usr/bin", "HOME=/home/roy", "LC_ALL=zh_TW.UTF-8", "SLIDEWORK_HOME=/Users/roy/slidework"} {
		if !strings.Contains(got, want) {
			t.Errorf("少了 %q：\n%s", want, got)
		}
	}
	// 祕密、會改寫連線目標的東西、以及想不到的變數，一律不給。
	for _, never := range []string{"OPENAI_API_KEY", "COPILOT_DESKTOP_TOKEN", "UNIEAI_BASE_URL", "HTTPS_PROXY", "SOME_RANDOM_THING", "SNEAKY_TOKEN", "bad name"} {
		if strings.Contains(got, never) {
			t.Errorf("不該有 %q：\n%s", never, got)
		}
	}
}
