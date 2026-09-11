package envguard

import (
	"strings"
	"testing"
)

// 子行程拿得到什麼，是這個 daemon 最重要的一道門之一：代理人跑的指令如果
// 看得到 daemon 自己的憑證，前面所有的核准與關押都白做。

func envMap(kvs []string) map[string]string {
	m := map[string]string{}
	for _, kv := range kvs {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func TestChildEnvIsAnAllowList(t *testing.T) {
	got := envMap(ChildEnv([]string{
		"PATH=/usr/bin", "HOME=/home/roy", "LC_ALL=zh_TW.UTF-8",
		"SOMETHING_WE_NEVER_HEARD_OF=1", // 白名單之外
	}, nil))
	if got["PATH"] != "/usr/bin" || got["HOME"] != "/home/roy" || got["LC_ALL"] == "" {
		t.Fatalf("已知安全的沒放行：%v", got)
	}
	if _, ok := got["SOMETHING_WE_NEVER_HEARD_OF"]; ok {
		t.Fatal("白名單之外的被放行了 —— 黑名單對明天新增的變數永遠是錯的")
	}
}

func TestSecretsNeverPass(t *testing.T) {
	// 這些是威脅本身：金鑰外洩，以及被改寫的 base url／proxy 把流量導走。
	for _, k := range []string{
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "DB_PASSWORD",
		"MY_SECRET", "SOME_BASE_URL", "HTTPS_PROXY", "AVA_LOCAL_HOME",
		"openai_api_key", // 大小寫不該是繞過的方法
	} {
		got := envMap(ChildEnv([]string{k + "=x"}, nil))
		if _, ok := got[k]; ok {
			t.Fatalf("%s 流進子行程了", k)
		}
	}
}

func TestExtraCannotSmuggleSecretsPastTheList(t *testing.T) {
	// 呼叫端把祕密塞進 extra 繞過白名單，是這道門最可能被破的方式。
	got := envMap(ChildEnv(nil, map[string]string{
		"TERM":           "xterm-256color", // 正當的
		"OPENAI_API_KEY": "sk-live",        // 不正當
		"BAD NAME":       "x",              // 根本不是合法的名字
	}))
	if got["TERM"] != "xterm-256color" {
		t.Fatal("正當的 extra 沒進去")
	}
	if _, ok := got["OPENAI_API_KEY"]; ok {
		t.Fatal("extra 繞過了白名單")
	}
	if _, ok := got["BAD NAME"]; ok {
		t.Fatal("不合法的名字被放行")
	}
}

func TestGuardStartupRefusesTrafficRedirection(t *testing.T) {
	for name, env := range map[string][]string{
		"關掉 TLS 驗證": {"NODE_TLS_REJECT_UNAUTHORIZED=0"},
		"設了 proxy":  {"HTTPS_PROXY=http://evil:8080"},
		"改寫 app 網址": {"AVA_LOCAL_APP_URL=https://evil.example"},
	} {
		t.Run(name, func(t *testing.T) {
			v := GuardStartup("https://agent.dev.unieai.com", env)
			if v.OK {
				t.Fatalf("應該拒絕啟動：%+v", v)
			}
			if len(v.Problems) == 0 {
				t.Fatal("拒絕了但說不出原因")
			}
		})
	}
}

func TestProxyIsAllowedWhenTheUserSaysItIsHis(t *testing.T) {
	v := GuardStartup("https://a", []string{"HTTPS_PROXY=http://corp:3128", "AVA_LOCAL_ALLOW_PROXY=1"})
	if !v.OK {
		t.Fatalf("使用者明著說那是他公司的 proxy，不該擋：%+v", v)
	}
}

func TestSameAppUrlIsNotAnOverride(t *testing.T) {
	// 尾巴的斜線不是攻擊。
	v := GuardStartup("https://agent.dev.unieai.com", []string{"AVA_LOCAL_APP_URL=https://agent.dev.unieai.com/"})
	if !v.OK {
		t.Fatalf("同一個網址被當成覆蓋：%+v", v)
	}
}

func TestProviderKeyIsAWarningNotFatal(t *testing.T) {
	// 一個有裝 OPENAI_API_KEY 的開發者，daemon 要照常啟動 —— 我們不把它傳給
	// 工具，而那句話本身就是處置。混成致命的話這個人根本跑不起來。
	v := GuardStartup("https://a", []string{"OPENAI_API_KEY=sk-live"})
	if !v.OK {
		t.Fatal("供應商金鑰不該讓 daemon 啟動不了")
	}
	if len(v.Problems) != 1 || !strings.Contains(v.Problems[0], "不會把它傳給") {
		t.Fatalf("要說出來，而且要說清楚處置是什麼：%+v", v.Problems)
	}
}
