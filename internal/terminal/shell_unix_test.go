//go:build !windows

package terminal

import "testing"

func TestResolveShell(t *testing.T) {
	exists := func(paths ...string) func(string) bool {
		set := map[string]bool{}
		for _, p := range paths {
			set[p] = true
		}
		return func(p string) bool { return set[p] }
	}

	if got, err := resolveShell(map[string]string{"SHELL": "/usr/bin/fish"}, exists("/usr/bin/fish", "/bin/sh")); err != nil || got != "/usr/bin/fish" {
		t.Errorf("$SHELL 應該優先，得到 %q / %v", got, err)
	}
	// 相對路徑的 $SHELL 一律忽略：那個搜尋會用 daemon 的 PATH，找到一個同名的
	// 別的執行檔比退回 /bin/sh 更糟。
	if got, _ := resolveShell(map[string]string{"SHELL": "fish"}, exists("fish", "/bin/bash", "/bin/sh")); got == "fish" {
		t.Error("相對路徑的 $SHELL 不該被採用")
	}
	if got, err := resolveShell(map[string]string{}, exists("/bin/sh")); err != nil || got != "/bin/sh" {
		t.Errorf("該退回 /bin/sh，得到 %q / %v", got, err)
	}
	if _, err := resolveShell(map[string]string{}, exists()); CodeOf(err) != CodeNoShell {
		t.Errorf("一個 shell 都沒有應該回 %s，得到 %v", CodeNoShell, err)
	}
}
