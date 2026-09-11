package confine

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// container.go —— 把指令丟進使用者**自己電腦上**的容器，只掛載授權資料夾。
//
// 為什麼還要有這一種：原生那一層（native.go）只在 Linux 與 macOS 有，Windows
// 完全沒有；而且原生那層擋的是「寫到授權資料夾外面」，擋不了「把這台機器本身
// 改掉」—— apt-get install、npm i -g、多起一個服務。那些是使用者沒有要求、
// 事後也看不到的副作用：一張寫著 `npm install` 的核准卡，不會說「順便會寫
// ~/.npm 和 /usr/local/lib」。
//
// 掛載授權資料夾到 /workspace 再在容器裡跑，agent 做的事就只會落在使用者選的
// 那個資料夾裡，不然就哪裡都不落。要改這台機器本身，變成他得明著要求的事。
//
// **這不是對付惡意 agent 的安全邊界**：容器跟主機共用核心，掛進去的資料夾是
// 真的可寫的（那正是重點）。它是一個熱心的 agent 跑了一條比核准卡上寫得更多的
// 指令時，爆炸範圍的邊界。
//
// **網路預設留著**。使用者最常要 agent 做的事就是「裝一裝相依然後跑測試」，
// 而這裡買的是機器**狀態**的保護，不是出口流量。Network: "none" 給兩個都要的人。

// ContainerRuntime 是 docker 或 podman。
type ContainerRuntime string

const (
	RuntimeDocker ContainerRuntime = "docker"
	RuntimePodman ContainerRuntime = "podman"
)

// DefaultImage 刻意小而無聊：它會被下載到某個人的筆電上，一個 5GB 的
// 「什麼都有」映像是很糟的第一印象。
const DefaultImage = "debian:stable-slim"

// DetectContainerRuntime 找出這台機器有哪一種容器執行環境，優先 rootless 的 podman。
//
// 用 `info` 而不是 `--version`：一個沒有 daemon 可連的 docker CLI 會很開心地
// 回答 --version，然後在第一條真的指令上失敗。
//
// 而且**輸出必須非空**，不能只看離開碼是 0。一台裝了 Docker Desktop 但沒開的
// Mac 上，`docker info` 可以離開碼 0 卻什麼都不印 —— 那會被讀成「可用」，
// 然後在第一次 pull 就死在 "Cannot connect to the Docker daemon"。
// 這是在真的機器上看到的（TS 版，2026-09-02）。
func DetectContainerRuntime() (ContainerRuntime, bool) {
	for _, bin := range []ContainerRuntime{RuntimePodman, RuntimeDocker} {
		out, err := runWithTimeout(5*time.Second, string(bin), "info", "--format", "{{.ServerVersion}}")
		if err != nil {
			continue
		}
		if strings.TrimSpace(out) == "" {
			continue
		}
		return bin, true
	}
	return "", false
}

// HasImage 回報映像在不在本機。沒先問就拉幾百 MB 是很沒禮貌的事。
func HasImage(rt ContainerRuntime, image string) bool {
	out, err := runWithTimeout(10*time.Second, string(rt), "image", "inspect", image)
	return err == nil && len(strings.TrimSpace(out)) > 0
}

// ContainerOptions 是容器關押的設定。
type ContainerOptions struct {
	Runtime ContainerRuntime
	Image   string
	// Network "bridge"（預設）留著網路；"none" 切斷。
	Network string
	// User 是容器裡用哪個 uid:gid 跑，讓掛載目錄裡的檔案還是使用者的。
	// Windows 上留空（那邊沒有這個概念）。
	User string
}

type containerConfine struct{ opts ContainerOptions }

func (c *containerConfine) Name() string {
	return fmt.Sprintf("container(%s:%s)", c.opts.Runtime, c.opts.Image)
}

// When 見 Mode：起容器要時間，而且容器裡不一定有使用者專案要的 toolchain，
// 所以這一種是等 agent 開口才用。
func (c *containerConfine) When() Mode { return ModeOnRequest }

func (c *containerConfine) Wrap(argv []string, opts Options) (Command, error) {
	if len(argv) == 0 {
		return Command{}, fmt.Errorf("confine: 沒有指定要執行什麼")
	}
	if opts.Root == "" {
		return Command{}, fmt.Errorf("confine: 沒有授權資料夾，沒有東西可以掛進容器")
	}
	cwd := opts.Cwd
	if cwd == "" {
		cwd = opts.Root
	}
	network := c.opts.Network
	if network == "" {
		network = "bridge"
	}
	args := []string{"run", "--rm", "-i", "--network", network}
	if c.opts.User != "" {
		args = append(args, "--user", c.opts.User)
	}
	args = append(args,
		// 授權資料夾，其他什麼都沒有。沒有家目錄、沒有 /etc、沒有 socket。
		"-v", opts.Root+":/workspace",
		"-w", ContainerPath(opts.Root, cwd),
		// 跑掉的迴圈不該把整台筆電一起帶走。
		"--pids-limit", "512",
		c.opts.Image,
	)
	args = append(args, argv...)
	return Command{
		Argv: append([]string{string(c.opts.Runtime)}, args...),
		// 主機端的 cwd 在 -w 決定了容器裡從哪裡開始之後就沒有意義了，
		// 但它仍然必須**存在**，否則連 spawn 本身都會失敗。
		Dir: opts.Root,
	}, nil
}

// NewContainer 建一個容器關押。Runtime 或 Image 沒填會用預設值。
func NewContainer(opts ContainerOptions) Confinement {
	if opts.Runtime == "" {
		opts.Runtime = RuntimeDocker
	}
	if opts.Image == "" {
		opts.Image = DefaultImage
	}
	return &containerConfine{opts: opts}
}

// ContainerPath 把主機上的路徑翻成容器裡的路徑。
//
// 工作目錄要**翻譯**，不是原樣傳過去：主機的 /home/me/proj/src 在容器裡是
// /workspace/src。把主機路徑交給 -w，得到的是一個從不存在的目錄啟動的容器，
// 而那個失敗看起來會像是使用者的指令寫錯了。
//
// Windows 的主機路徑（C:\Users\me\proj\src）也走這裡：分隔符要換成 /，
// 因為容器裡是 Linux。
func ContainerPath(root, hostPath string) string {
	rel, err := filepath.Rel(root, hostPath)
	if err != nil || rel == "" || rel == "." {
		return "/workspace"
	}
	// 跑到 root 外面照理說不可能（scope 先跑過了），真的發生的話退回掛載點，
	// 而不是讓它逃出容器。
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "/workspace"
	}
	return path.Join("/workspace", strings.ReplaceAll(rel, string(filepath.Separator), "/"))
}
