// Package relay 是這個程式和雲端之間唯一的通道。
//
// 方向是**這台電腦主動撥出去**。使用者的機器在 NAT 後面，雲端進不來 ——
// 這不是設定問題，是網路結構。所以連線由這一側建立、由這一側維持，
// 也由這一側結束（使用者按「停止」就是真的斷掉，雲端叫不醒它）。
//
// 傳輸是 SSE 下行 + POST 上行，不是 WebSocket。理由：它穿得過任何 HTTP 反向代理
// （這個部署前面是 Caddy），不需要 upgrade 協商。伺服器那側的登記簿是
// transport-agnostic 的，之後要換 WebSocket 只換這個檔案。
package relay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Client struct {
	ServerURL string // 例如 https://agent.unieai.com
	MachineID string
	// Ticket 取得一張目前有效的短命身分憑證。每次重連都會重新要一張 ——
	// 憑證會過期，而重連往往發生在電腦睡了好幾個小時之後。
	Ticket func(ctx context.Context) (string, error)
	HTTP   *http.Client

	// OnMessage 收到一則下行訊息。在自己的 goroutine 裡跑，不要阻塞。
	OnMessage func(Down)
	// OnState 連線狀態變化，給工具列用。
	OnState func(connected bool, detail string)
	// OnRevoke 這台電腦在網頁上被移除了。**這跟斷線不一樣**：重連只會拿到
	// 401，而使用者會看著它永遠重試而沒有任何一句話說明。收到就清掉憑證、
	// 說一句、退出。
	OnRevoke func(reason string)

	mu  sync.Mutex
	jwt string
	// 上行一次一個，**照順序**。批次曾經是為了省往返，但這條路上
	// 「輸出」與「結束」的先後是語意的一部分：結束一落地，relay 就把待辦
	// 刪掉，被超車的輸出會撞上「找不到這個 id」然後靜靜消失。
	sendMu   sync.Mutex
	queue    []Result
	draining bool
}

// errRevoked 讓重連迴圈知道「這不是斷線，是被收回了」——
// 退避重連對一張已經作廢的憑證沒有任何幫助。
var errRevoked = errors.New("這台電腦已經在網頁上被移除")

// ErrUnauthorized：伺服器明著拒絕了這張憑證。呼叫端要分得出它與「連不上」——
// 兩者混用的兩個方向都糟：當成連不上就會永遠重試，當成被移除就會在 app
// 重開機的那三十秒把所有人的配對清掉。
var ErrUnauthorized = errors.New("憑證被拒絕")

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	// 下行是一條長連線，**不能設整體 timeout**，否則每隔 N 秒就會被自己切斷。
	// 逾時控制交給 context 與伺服器的心跳。
	return &http.Client{}
}

// Run 維持連線直到 ctx 結束。斷了就重連，退避從 1 秒到 30 秒。
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := c.connectOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		// 被收回了就別再重連。退避對一張已經作廢的憑證沒有幫助，而使用者
		// 看到的會是「它一直在連、一直連不上」，沒有任何一句話說明。
		if errors.Is(err, errRevoked) {
			if c.OnState != nil {
				c.OnState(false, err.Error())
			}
			return
		}
		detail := "連線中斷"
		if err != nil {
			detail = err.Error()
		}
		if c.OnState != nil {
			c.OnState(false, detail)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (c *Client) connectOnce(ctx context.Context) error {
	jwt, err := c.Ticket(ctx)
	if err != nil {
		return fmt.Errorf("取得憑證失敗：%w", err)
	}
	c.mu.Lock()
	c.jwt = jwt
	c.mu.Unlock()

	url := strings.TrimRight(c.ServerURL, "/") + "/api/machines/relay/connect"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// **身分在 bearer 裡，machineId 不上線路。** app 用這張 token 解析出唯一
	// 一列 user_machines；讓呼叫端在 query 裡宣告自己是哪一台，正是 ava 分支
	// 否決掉舊設計的理由（見 protocol.go 的檔頭）。
	req.Header.Set("authorization", "Bearer "+jwt)
	req.Header.Set("accept", "text/event-stream")
	req.Header.Set("user-agent", "rabi-local-go/"+Version)

	res, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		// 憑證被明著拒絕。**跟「連不上」不是同一件事** —— 前者重連一萬次
		// 也不會好，而使用者的磁碟上還留著一份設定。交給呼叫端決定要不要
		// 換一張、或當成已經被移除。
		return fmt.Errorf("%w（HTTP %d）", ErrUnauthorized, res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("伺服器回 HTTP %d", res.StatusCode)
	}

	// SSE：一則訊息以空行結束，內容在 "data: " 之後。註解行（": ping"）忽略。
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var data strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if data.Len() > 0 {
				var msg Down
				if err := json.Unmarshal([]byte(data.String()), &msg); err == nil {
					switch msg.Type {
					case "ready":
						if c.OnState != nil {
							c.OnState(true, "")
						}
					case "revoke":
						// 這台電腦在網頁上被移除了。**這不是斷線** ——
						// 重連只會拿到 401，而使用者會看著它永遠重試。
						if c.OnRevoke != nil {
							c.OnRevoke(msg.Reason)
						}
						return errRevoked
					case "ping", "":
						// 心跳，或我們不認得的東西。不認得就忽略，不要當錯誤：
						// 伺服器加一種新訊息不該讓舊的客戶端整條斷線。
					default:
						if c.OnMessage != nil {
							go c.OnMessage(msg)
						}
					}
				}
				data.Reset()
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue // 心跳
		}
		if v, ok := strings.CutPrefix(line, "data: "); ok {
			data.WriteString(v)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("連線被伺服器關閉")
}

// Send 把一則結果排進上行佇列。
//
// **一條佇列、一次一個 POST、照排進來的順序。** 不是效能取捨，是語意：
// partial 的輸出必須在最終結果之前落地（見 protocol.go 的 Result）。
func (c *Client) Send(r Result) {
	c.sendMu.Lock()
	c.queue = append(c.queue, r)
	if c.draining {
		c.sendMu.Unlock()
		return
	}
	c.draining = true
	c.sendMu.Unlock()
	go c.drain()
}

func (c *Client) drain() {
	for {
		c.sendMu.Lock()
		if len(c.queue) == 0 {
			c.draining = false
			c.sendMu.Unlock()
			return
		}
		next := c.queue[0]
		c.queue = c.queue[1:]
		c.sendMu.Unlock()
		c.postResult(next)
	}
}

// postResult 送一則。**失敗不重試也不卡住後面的** —— 對面有逾時，而一條卡住
// 的佇列會把「掉一個封包」變成「終端機從此不說話」。
func (c *Client) postResult(r Result) {
	c.mu.Lock()
	jwt := c.jwt
	c.mu.Unlock()
	if jwt == "" {
		return
	}
	body, err := json.Marshal(r)
	if err != nil {
		return
	}
	url := strings.TrimRight(c.ServerURL, "/") + "/api/machines/relay/result"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("content-type", "application/json")
	// **身分在 bearer 裡，不在 query 裡。** machineId 從來不是呼叫端說了算的
	// 東西 —— app 用這張 token 解析出唯一一列 user_machines（見 protocol.go）。
	req.Header.Set("authorization", "Bearer "+jwt)
	req.Header.Set("user-agent", "rabi-local-go/"+Version)
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err == nil {
		res.Body.Close()
	}
}

// Version 會回報給伺服器，之後對版與 OTA 都靠它。
var Version = "0.1.0"
