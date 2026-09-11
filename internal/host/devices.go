package host

import (
	"fmt"

	"github.com/UnieAI/Rabi-local/internal/devicekeys"
	"github.com/UnieAI/Rabi-local/internal/relay"
)

// devices.go —— 裝置簽的核准，它的兩個管理 op。
//
// # 這兩個為什麼不看核准票
//
// deviceList 是**唯讀而且裡面沒有秘密**：公鑰就是公鑰，credentialId 是瀏覽器
// 用來指名「用哪一把簽」的東西（allowCredentials）。
//
// deviceEnroll **自己就是簽章驗證**：VerifyEnrollment 要嘛看到一把已經信任的
// 金鑰簽過這次請求，要嘛這台機器一把都還沒有（第一把＝配對時人就在電腦前）。
// 拿核准票去擋它反而是錯的 —— 第一把金鑰進來之前，這台機器根本收不到任何一張
// 裝置票，那會變成一個沒有人打得開的門。
//
// 雲端在這條路上說什麼都不算數：它連自己的公鑰都加不進來，而那是整個方案的支點。

// deviceEntry 是回給雲端的一把金鑰。**沒有公鑰本身** —— 畫面用不到，而少送一樣
// 東西就少一個要想清楚的問題。
type deviceEntry struct {
	CredentialID string  `json:"credentialId"`
	Label        *string `json:"label"`
	AddedAt      string  `json:"addedAt"`
}

func (h *Host) deviceEntries() []deviceEntry {
	list := h.devices.List()
	out := make([]deviceEntry, 0, len(list))
	for _, d := range list {
		out = append(out, deviceEntry{CredentialID: d.CredentialID, Label: d.Label, AddedAt: d.AddedAt})
	}
	return out
}

// deviceList 是這台電腦信任哪幾把裝置公鑰。
func (h *Host) deviceList(inv relay.Invoke) relay.Result {
	if h.devices == nil {
		return relay.Fail(inv.ID, "device_approval_disabled", "這一版的 Rabi Local 不做裝置簽的核准。")
	}
	da := h.Posture().DeviceApproval
	return relay.Done(inv.ID, map[string]any{
		"devices":         h.deviceEntries(),
		"deviceOnly":      da.DeviceOnly,
		"deviceOnlySince": da.Since,
		// 權限不對要**端出去**：使用者唯一看得到的地方是雲端的畫面，daemon 的
		// log 在他自己的機器上而他不會去看。
		"unsafe": da.Unsafe,
	})
}

// deviceEnroll 加一把新的公鑰，或撤掉一把。
//
// frame 上的 enrollment 是**一整串已經簽好的意圖**，原樣拿去驗 —— 中間任何一層
// 改了一個位元，簽章就對不上。所以 app 是郵差，不是決定者，而規則一條都不在
// 這裡：全部交給 devicekeys.VerifyEnrollment。
func (h *Host) deviceEnroll(inv relay.Invoke, args map[string]any) relay.Result {
	if h.devices == nil {
		return relay.Fail(inv.ID, "device_approval_disabled", "這一版的 Rabi Local 不做裝置簽的核准。")
	}
	enrollment := argString(args, "enrollment")
	if enrollment == "" {
		return relay.Fail(inv.ID, "bad_request", "deviceEnroll 要帶 enrollment")
	}
	// by 不是物件（或是陣列）就是 nil，也就是「本機當面確認」。這一步不能省：
	// 一個亂寫的 by 會掉進本機確認那一條，而那是一條把註冊送給任何人的捷徑。
	by := devicekeys.AssertionFrom(args["by"])

	op, credentialID, err := h.devices.Apply(enrollment, by)
	if err != nil {
		// 被拒絕的註冊**一定要留下稽核列**：這是使用者事後唯一看得出「有人想把
		// 一把不是我的金鑰加進我的機器」的地方。
		h.audit("deviceEnroll", "refused: "+err.Error(), "refused", "")
		return relay.Fail(inv.ID, "device_enroll_rejected", "註冊被拒絕："+err.Error())
	}
	h.audit("deviceEnroll", op+" "+short(credentialID), "run", "")
	h.logf("裝置金鑰 %s：%s（現在有 %d 把）", op, short(credentialID), len(h.devices.List()))

	da := h.Posture().DeviceApproval
	return relay.Done(inv.ID, map[string]any{
		"op":              op,
		"devices":         h.deviceEntries(),
		"deviceOnly":      da.DeviceOnly,
		"deviceOnlySince": da.Since,
	})
}

// short 是一個 credentialId 在日誌裡的樣子 —— 完整的那一串又長又沒人讀得完。
func short(id string) string {
	if len(id) <= 12 {
		return id
	}
	return fmt.Sprintf("%s…", id[:12])
}
