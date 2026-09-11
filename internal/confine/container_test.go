package confine

import (
	"strings"
	"testing"
)

func TestContainerPath(t *testing.T) {
	root := "/home/u/work"
	cases := map[string]string{
		root:                   "/workspace",
		root + "/src":          "/workspace/src",
		root + "/src/a/b.txt":  "/workspace/src/a/b.txt",
		"/home/u/elsewhere":    "/workspace", // 照理說不可能（scope 先跑過），真的發生就退回掛載點
		"/home/u/work-other/x": "/workspace", // 字首像但不是子目錄
	}
	for host, want := range cases {
		if got := ContainerPath(root, host); got != want {
			t.Errorf("%s → %s，預期 %s", host, got, want)
		}
	}
}

func TestContainerWrap(t *testing.T) {
	c := NewContainer(ContainerOptions{Runtime: RuntimePodman, Image: "debian:stable-slim", User: "1000:1000"})
	cmd, err := c.Wrap([]string{"bash", "-lc", "npm ci"}, Options{Root: "/home/u/work", Cwd: "/home/u/work/src"})
	if err != nil {
		t.Fatal(err)
	}
	bin, _ := cmd.Split()
	if bin != "podman" {
		t.Errorf("執行的應該是 podman，得到 %q", bin)
	}
	joined := strings.Join(cmd.Argv, " ")
	for _, want := range []string{
		"-v /home/u/work:/workspace", // 只掛授權資料夾，沒有家目錄、沒有 /etc
		"-w /workspace/src",          // 工作目錄要翻譯，原樣傳過去會落在不存在的路徑
		"--network bridge",           // 預設留著網路（裝相依、跑測試）
		"--pids-limit 512",
		"--user 1000:1000",
		"debian:stable-slim bash -lc npm ci",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv 少了 %q\n實際：%s", want, joined)
		}
	}
	// 主機端的 cwd 必須存在，否則連 spawn 都會失敗。
	if cmd.Dir != "/home/u/work" {
		t.Errorf("主機端 cwd 應該是掛載來源，得到 %q", cmd.Dir)
	}
	if c.When() != ModeOnRequest {
		t.Error("容器是等 agent 開口才用的 —— 預設全開會讓一般指令莫名其妙失敗")
	}
	if !strings.Contains(c.Name(), "podman") || !strings.Contains(c.Name(), "debian") {
		t.Errorf("名字要說得出是哪一種、哪個映像，得到 %q", c.Name())
	}
}

func TestContainerNetworkNone(t *testing.T) {
	c := NewContainer(ContainerOptions{Runtime: RuntimeDocker, Image: "x", Network: "none"})
	cmd, err := c.Wrap([]string{"true"}, Options{Root: "/r"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(cmd.Argv, " "), "--network none") {
		t.Error("要求切斷網路卻沒有切")
	}
}

func TestContainerDefaults(t *testing.T) {
	c := NewContainer(ContainerOptions{})
	if !strings.Contains(c.Name(), string(RuntimeDocker)) || !strings.Contains(c.Name(), DefaultImage) {
		t.Errorf("預設值不對：%q", c.Name())
	}
	if _, err := c.Wrap([]string{"true"}, Options{Root: ""}); err == nil {
		t.Error("沒有授權資料夾就沒有東西可以掛，不該包得出來")
	}
}
