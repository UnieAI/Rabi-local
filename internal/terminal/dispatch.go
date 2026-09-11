package terminal

import (
	"encoding/base64"
	"errors"
	"strconv"
)

// 這個檔案是**對外的接線點**：main.go 只要認得 Frame / Result 兩個型別，就能把
// 雲端送下來的 terminal* 交給這個套件，不必知道 PTY、捲動緩衝或核准票的事。
//
// 線路的形狀照 runtime/packages/ava-local-protocol/src/protocol.mjs：
//
//	terminalOpen   { cwd?, cols?, rows?, env? }
//	               **這一次呼叫要到 shell 結束才會回來**，終端機這一生說的每一
//	               句話都以 partial 的形式走這同一個呼叫（雲端的 relay 是用
//	               invoke id 對應的，另開一條通道等於多一個會錯的東西）。
//	terminalInput  { id, dataBase64 }
//	terminalResize { id, cols, rows }
//	terminalSignal { id, signal }
//	terminalClose  { id }
//	terminalReplay { id }
//
// 輸出是**原始位元組的 base64**，由瀏覽器裡的終端機模擬器解碼，中間沒有人解。
// base64 只在這一層出現 —— 它是線路的事，不是終端機的事。
//
// # 接線長什麼樣子（main.go 之後要寫的那幾行）
//
//	term := terminal.New(terminal.Options{
//	    Root:    roots[0],
//	    Contain: scope, // *runner.Scope 本身就滿足 terminal.Contain
//	    Approval: terminal.GateFunc(func(tool, payloadHash, approval string) (string, error) {
//	        d := gate.Require(approval, devicekeys.Expect{Tool: tool, PayloadHash: payloadHash})
//	        switch {
//	        case d.Allow:
//	            return d.ActionID, nil
//	        case d.DelegateHMAC:
//	            return verifyHMACTicket(approval, tool, payloadHash) // app 簽的那一種
//	        default:
//	            return "", &terminal.Error{Code: d.Code, Message: d.Message}
//	        }
//	    }),
//	    Audit: audit.Append,
//	})
//	defer term.CloseAll() // 活過 daemon 的 shell 是沒有人叫得動的行程
//
// 然後在收到 invoke 的地方：terminal.Handles(op) 為真就交給 term.Dispatch，
// **而且 terminalOpen 要放在自己的 goroutine 裡**（它到 shell 結束才回來）。

// Frame 是雲端送下來的一次呼叫。
type Frame struct {
	// ID 是這一次呼叫的編號。terminalOpen 沒有給 terminalId 的時候，
	// **這個編號就是終端機的名字**（雲端之後就用它當 args.id）。
	ID   string
	Op   string
	Args map[string]any
	// Approval 是使用者按下允許之後，app 簽出來的那張票。
	Approval string
}

// Result 是回給雲端的結果。ok=false 的時候 Output 裡是 {"error": {code, message}}。
type Result struct {
	OK     bool
	Output map[string]any
}

// Ops 是這個套件負責的 op 名字。
var dispatchOps = map[string]bool{
	"terminalOpen": true, "terminalInput": true, "terminalResize": true,
	"terminalSignal": true, "terminalClose": true, "terminalReplay": true,
}

// Handles 回報一個 op 是不是這個套件的。
func Handles(op string) bool { return dispatchOps[op] }

// Dispatch 執行一個 terminal* 呼叫。
//
// emit 收到的是**已經是線路形狀**的 partial：輸出是 {"dataBase64": "…"}，
// 而 opened 與 alive 包在 {"terminal": {…}} 裡面 —— 這樣一個在找輸出的消費端
// 不可能把它們誤認成輸出。
//
// **terminalOpen 會擋住到 shell 結束為止**（其他五個立刻回來），所以呼叫端要
// 在自己的 goroutine 裡叫它，就像它對一個長跑的 exec 做的那樣。
func (s *Service) Dispatch(f Frame, emit func(map[string]any)) Result {
	switch f.Op {
	case "terminalOpen":
		return s.dispatchOpen(f, emit)
	case "terminalInput":
		n, err := s.Input(handleID(f), decodeBase64(argString(f.Args, "dataBase64"), argString(f.Args, "data")))
		if err != nil {
			return failure(err)
		}
		return Result{OK: true, Output: map[string]any{"bytes": n}}
	case "terminalResize":
		view, err := s.Resize(handleID(f), argInt(f.Args, "cols"), argInt(f.Args, "rows"))
		if err != nil {
			return failure(err)
		}
		return Result{OK: true, Output: map[string]any{"cols": view.Cols, "rows": view.Rows}}
	case "terminalSignal":
		delivered, err := s.Signal(handleID(f), upper(argString(f.Args, "signal", "SIGINT")))
		if err != nil {
			return failure(err)
		}
		return Result{OK: true, Output: map[string]any{"delivered": delivered}}
	case "terminalClose":
		return Result{OK: true, Output: map[string]any{"closed": s.Close(handleID(f))}}
	case "terminalReplay":
		data, err := s.Replay(handleID(f))
		if err != nil {
			return failure(err)
		}
		return Result{OK: true, Output: map[string]any{"dataBase64": base64.StdEncoding.EncodeToString(data)}}
	}
	return failure(errf(CodeBadRequest, "不是終端機的 op：%s", f.Op))
}

func (s *Service) dispatchOpen(f Frame, emit func(map[string]any)) Result {
	terminalID := argString(f.Args, "terminalId", f.ID)
	exited := make(chan Result, 1)

	_, err := s.Open(OpenRequest{
		TerminalID: terminalID,
		Cwd:        argString(f.Args, "cwd"),
		Env:        argStringMap(f.Args, "env"),
		Cols:       argInt(f.Args, "cols"),
		Rows:       argInt(f.Args, "rows"),
		Approval:   f.Approval,
	}, func(e Event) {
		switch e.Event {
		case "data":
			// **線路的形狀是雲端的，不是這裡的。** relay 從 partial 的最上層讀
			// ev.dataBase64、從最後的結果讀 output.exit —— 跟一個 exec 一樣的
			// 兩個形狀。包一個比較漂亮的巢狀信封，兩邊都會編譯過，然後開出一個
			// 打得了字、但什麼都看不到的終端機。
			if emit != nil {
				emit(map[string]any{"dataBase64": base64.StdEncoding.EncodeToString(e.Data)})
			}
		case "exit":
			// exit 是**最後的結果**，不是 partial。兩個都送的話，遠端會看到這個
			// 終端機結束兩次，而第二次到的時候那個呼叫早就不在了。
			s.Forget(e.TerminalID)
			exited <- Result{OK: true, Output: map[string]any{
				"exit":     map[string]any{"code": e.ExitCode, "signal": nil},
				"terminal": wireEvent(e),
			}}
		default:
			if emit != nil {
				emit(map[string]any{"terminal": wireEvent(e)})
			}
		}
	})
	if err != nil {
		return failure(err)
	}
	return <-exited
}

// wireEvent 把一個事件變成線路上的形狀。
func wireEvent(e Event) map[string]any {
	switch e.Event {
	case "opened":
		return map[string]any{
			"event": "opened", "terminalId": e.TerminalID, "pid": e.PID,
			"cwd": e.Cwd, "shell": e.Shell, "title": e.Title, "cols": e.Cols, "rows": e.Rows,
		}
	case "exit":
		return map[string]any{
			"event": "exit", "terminalId": e.TerminalID,
			"exitCode": e.ExitCode, "closedByClient": e.ClosedByClient,
		}
	default:
		return map[string]any{"event": e.Event, "terminalId": e.TerminalID}
	}
}

// handleID 是一個後續呼叫指名的那個終端機。
//
// 雲端用**開啟那一次的 invoke id** 當把手（args.id），跟一個長跑行程用的是同一根
// 釘子；daemon 自己的名字叫 terminalId。兩種拼法都收 —— 只有一邊拼對的把手，
// 症狀是按鍵消失、而且哪裡都沒有錯誤。
func handleID(f Frame) string {
	return argString(f.Args, "terminalId", argString(f.Args, "id"))
}

func failure(err error) Result {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Code: "internal", Message: err.Error()}
	}
	return Result{OK: false, Output: map[string]any{
		"error": map[string]any{"code": e.Code, "message": e.Message},
	}}
}

/* ---------- 從 JSON 解出來的 map 裡取值 ---------- */

func argString(args map[string]any, key string, fallback ...string) string {
	if v, ok := args[key].(string); ok && v != "" {
		return v
	}
	for _, f := range fallback {
		if f != "" {
			return f
		}
	}
	return ""
}

// argInt 收 JSON 的數字（解出來一律是 float64）也收字串。取不到就回 0，
// 由 clampSize 去決定用什麼預設值 —— 尺寸是夾住的，不是拒絕的。
func argInt(args map[string]any, key string) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		n := 0
		for _, c := range v {
			if c < '0' || c > '9' {
				return 0
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return 0
}

func argStringMap(args map[string]any, key string) map[string]string {
	raw, ok := args[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		// 跟 canonical.mjs 的 String(val) 對齊：**兩邊要算出同一個 subject**，
		// 所以數字與布林值要變成 JS 會變成的那個字串，不能靜靜丟掉（丟掉的
		// 症狀是 payload_mismatch，一個看起來像「票壞了」的錯誤）。
		// 物件與 null 這裡不收 —— JS 會把它們變成 "[object Object]"／"null"，
		// 而那種東西出現在環境變數裡，本身就是一個該被拒絕的請求。
		switch t := v.(type) {
		case string:
			out[k] = t
		case bool:
			if t {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		case float64:
			out[k] = strconv.FormatFloat(t, 'g', -1, 64)
		}
	}
	return out
}

func decodeBase64(values ...string) []byte {
	for _, v := range values {
		if v == "" {
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(v); err == nil {
			return b
		}
	}
	return nil
}

func upper(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= 'a' && r <= 'z' {
			out[i] = r - 32
		}
	}
	return string(out)
}
