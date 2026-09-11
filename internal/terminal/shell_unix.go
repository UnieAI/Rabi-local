//go:build !windows

package terminal

import (
	"os"
	"strings"
)

// shellCandidates 是 unix 上要依序試的程式。
//
// 使用者自己的 $SHELL 排第一 —— 他的提示字元、他的 alias、他的補完都在那裡面。
// 只有絕對路徑算數（見 resolveShell）。
func shellCandidates(env map[string]string) []string {
	out := make([]string, 0, 3)
	if s := env["SHELL"]; strings.HasPrefix(s, "/") {
		out = append(out, s)
	}
	return append(out, "/bin/bash", "/bin/sh")
}

func isExecutable(info os.FileInfo) bool { return info.Mode()&0o111 != 0 }
