package confine

import (
	"strings"
	"testing"
)

// Choose 的測試重點只有一個：**降級有沒有被照實講出來**。
//
// 一個相信自己被關押、實際上沒有的人，處境比知道自己沒有的人更糟 ——
// 所以「退回沒有關押」這條路必須帶著 Degraded 與一句人話，而那是程式邏輯，
// 驗得到。
func stub(t *testing.T, native func() (Kind, string, string), rt func() (ContainerRuntime, bool), img func(ContainerRuntime, string) bool) {
	t.Helper()
	on, or, oi := detectNativeFn, detectContainerFn, hasImageFn
	if native != nil {
		detectNativeFn = native
	}
	if rt != nil {
		detectContainerFn = rt
	}
	if img != nil {
		hasImageFn = img
	}
	t.Cleanup(func() { detectNativeFn, detectContainerFn, hasImageFn = on, or, oi })
}

func TestChooseNativeAvailable(t *testing.T) {
	stub(t, func() (Kind, string, string) { return KindBwrap, "/usr/bin/bwrap", "" }, nil, nil)
	c, n := Choose(Preference{})
	if c.Name() != "bwrap" || c.When() != ModeAlways {
		t.Errorf("應該用原生關押，得到 %q/%q", c.Name(), c.When())
	}
	if n.Degraded {
		t.Error("拿到預期的關押卻標成降級")
	}
}

func TestChooseNativeMissingSaysWhy(t *testing.T) {
	stub(t, func() (Kind, string, string) { return KindNone, "", "這台機器上找不到 bwrap。裝上之後…" }, nil, nil)
	c, n := Choose(Preference{})
	if c.Name() != "none" {
		t.Errorf("沒有關押就該回 none，得到 %q", c.Name())
	}
	if !n.Degraded {
		t.Fatal("完全沒有關押卻沒有標成降級 —— 這正是「以為有保護，其實沒有」")
	}
	if !strings.Contains(n.Message, "bwrap") {
		t.Errorf("沒有說出原因：%q", n.Message)
	}
	// posture 也要跟著說實話，不然畫面上會打勾。
	if p := PostureOf(c, "/r", false); p.SecretsHidden || p.Confinement != "none" {
		t.Errorf("posture 說謊了：%+v", p)
	}
}

func TestChooseOffIsStillReported(t *testing.T) {
	stub(t, func() (Kind, string, string) { return KindBwrap, "/usr/bin/bwrap", "" }, nil, nil)
	c, n := Choose(Preference{Mode: "off"})
	if c.Name() != "none" {
		t.Errorf("明著關掉就是沒有關押，得到 %q", c.Name())
	}
	if !n.Degraded || !strings.Contains(n.Message, "off") {
		t.Errorf("使用者自己關掉的也要看得見：%+v", n)
	}
}

func TestChooseContainer(t *testing.T) {
	stub(t, nil,
		func() (ContainerRuntime, bool) { return RuntimePodman, true },
		func(ContainerRuntime, string) bool { return true })
	c, n := Choose(Preference{Mode: "container"})
	if !strings.Contains(c.Name(), "container(podman") {
		t.Errorf("應該用容器，得到 %q", c.Name())
	}
	if n.Degraded {
		t.Error("拿到要求的東西卻標成降級")
	}
}

func TestChooseContainerImageMissing(t *testing.T) {
	stub(t, nil,
		func() (ContainerRuntime, bool) { return RuntimeDocker, true },
		func(ContainerRuntime, string) bool { return false })
	c, n := Choose(Preference{Mode: "container"})
	// 映像沒拉不是「沒有關押」，是「一要求沙盒就會失敗」—— 兩種的補救方法不一樣。
	if !strings.Contains(c.Name(), "container(") {
		t.Errorf("關押本身還在，得到 %q", c.Name())
	}
	if !n.Degraded || !strings.Contains(n.Message, "pull") {
		t.Errorf("沒有講清楚要先拉映像：%+v", n)
	}
}

func TestChooseContainerFallsBackToNative(t *testing.T) {
	stub(t, func() (Kind, string, string) { return KindBwrap, "/usr/bin/bwrap", "" },
		func() (ContainerRuntime, bool) { return "", false }, nil)
	c, n := Choose(Preference{Mode: "container"})
	if c.Name() != "bwrap" {
		t.Errorf("沒有容器就退回原生，得到 %q", c.Name())
	}
	// 退了就要說退了：使用者要的是容器（連機器狀態都想保護），拿到的是寫入圍籬。
	if !n.Degraded || !strings.Contains(n.Message, "docker") {
		t.Errorf("退回沒有講：%+v", n)
	}
}
