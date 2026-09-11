// service.go —— 把授權清單與那幾條連線包成一個東西：list 與 call。
//
// 刻意只有這兩個方法。之後要補 HTTP transport 的時候，換掉的是 Conn 的實作，
// 授權／核准／稽核那三條完全不用動。
package mcp

import (
	"context"
	"sync"
	"time"
)

// ServerListing 是一台 server 在 mcpList 回去的樣子。欄位名字（JSON）跟雲端
// 的 MachineMcpServer 對齊，換一個字就是那一頭讀不到。
type ServerListing struct {
	ID          string  `json:"id"`
	Description *string `json:"description"`
	// ReadOnlyTools 要送上去，雲端才知道哪些工具**不會**跳核准卡。
	ReadOnlyTools []string         `json:"readOnlyTools"`
	Tools         []ToolDescriptor `json:"tools"`
	// Error 是**這一台**問不到工具的原因。一台起不來不該讓整份清單失敗 ——
	// 使用者的另外兩台還是能用，而壞掉的那一台要說得出為什麼。
	Error *string `json:"error"`
}

// Options 建一個 Service。
type Options struct {
	Grants      []Grant
	GrantErrors []string
	Log         Logger
	// Dial 注入用：測試不想真的 spawn 一個行程。給 nil 就是真的起 stdio。
	Dial func(Grant) Conn
	// RequestTimeout 單次 JSON-RPC 往返的預設上限（含握手）。0 → 60 秒。
	RequestTimeout time.Duration
}

// Service 是這台電腦上所有被授權的本機 MCP server。
type Service struct {
	grants  []Grant
	byID    map[string]Grant
	errs    []string
	log     Logger
	dial    func(Grant) Conn
	timeout time.Duration

	mu    sync.Mutex
	conns map[string]Conn
}

// New 建一個 Service。**只有 Enabled 的授權算數** —— 使用者把一台設成
// enabled:false 的意思就是「現在不要」，那跟沒寫是同一件事。
func New(opts Options) *Service {
	s := &Service{
		byID:    map[string]Grant{},
		errs:    opts.GrantErrors,
		log:     opts.Log,
		dial:    opts.Dial,
		timeout: opts.RequestTimeout,
		conns:   map[string]Conn{},
	}
	for _, g := range opts.Grants {
		if !g.Enabled {
			continue
		}
		s.grants = append(s.grants, g)
		s.byID[g.ID] = g
	}
	return s
}

// Available 說這台機器現在有沒有這個能力。有授權檔但一台都沒授權，跟根本沒有
// 那個檔案，對雲端是同一件事：「這台機器沒有本機 MCP 可以叫」。
func (s *Service) Available() bool { return len(s.grants) > 0 }

// GrantErrors 是授權檔自己的問題，給**使用者**看的，不是給模型看的。
func (s *Service) GrantErrors() []string { return s.errs }

// ServerIDs 是被授權的 server id。
func (s *Service) ServerIDs() []string {
	out := make([]string, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, g.ID)
	}
	return out
}

// GrantFor 查一台 server 的授權。**這是「雲端說得出什麼」的邊界**：查不到就
// 是沒授權，frame 上帶再多欄位也變不出一台 server。
func (s *Service) GrantFor(serverID string) (Grant, bool) {
	g, has := s.byID[lower(serverID)]
	return g, has
}

func (s *Service) connFor(g Grant) Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, has := s.conns[g.ID]; has {
		return c
	}
	var c Conn
	if s.dial != nil {
		c = s.dial(g)
	} else {
		c = newStdioConn(g, s.log, s.timeout)
	}
	s.conns[g.ID] = c
	return c
}

// List 問這幾台 server 現在有什麼工具。serverID 空字串就是全部。
//
// 這會把那些 server **起起來** —— 沒有別的辦法問一個 MCP server 有什麼工具。
// 起來的一定是授權檔裡寫死的那個指令，而且閒置之後會自己收。
func (s *Service) List(ctx context.Context, serverID string) []ServerListing {
	wanted := s.grants
	if serverID != "" {
		wanted = nil
		if g, has := s.GrantFor(serverID); has {
			wanted = []Grant{g}
		}
	}
	out := make([]ServerListing, 0, len(wanted))
	for _, g := range wanted {
		listing := ServerListing{ID: g.ID, ReadOnlyTools: g.ReadOnlyTools, Tools: []ToolDescriptor{}}
		if g.Description != "" {
			d := g.Description
			listing.Description = &d
		}
		tools, err := s.connFor(g).ListTools(ctx)
		if err != nil {
			m := err.Error()
			listing.Error = &m
		} else if tools != nil {
			listing.Tools = tools
		}
		out = append(out, listing)
	}
	return out
}

// Call 叫一次。**不做任何核准判斷** —— 那是 host.go 的事，而且順序不能換
// （先授權、再核准、才呼叫）。
func (s *Service) Call(ctx context.Context, serverID, tool string, args map[string]any, timeout time.Duration) (*CallOutcome, error) {
	g, has := s.GrantFor(serverID)
	if !has {
		return nil, errf("mcp_not_granted", "這台電腦上沒有授權過名叫「%s」的 MCP server", serverID)
	}
	return s.connFor(g).CallTool(ctx, tool, args, timeout)
}

// CloseAll 把所有子行程收掉。程式要結束、或使用者收回授權時叫它 —— 不叫的話
// 那些 server 會活過這個程式，而且之後沒有人碰得到。
func (s *Service) CloseAll() {
	s.mu.Lock()
	conns := s.conns
	s.conns = map[string]Conn{}
	s.mu.Unlock()
	for _, c := range conns {
		c.Close("daemon 收線")
	}
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
