package host

import "strconv"

// args.go —— 從 frame 上那包形狀不明的 JSON 取值。
//
// # 為什麼取值要這麼小心
//
// `Invoke.Args` 是雲端送下來的任意 JSON。解成 map[string]any 之後，數字一律是
// float64、缺的欄位是 nil、型別錯的欄位是別的東西。直接 type assert 而不給預設
// 值的話，一個少打欄位的請求會變成 panic —— 而 panic 在這條路上等於「那台機器
// 忽然不回話了」，使用者看到的跟真正的原因差很遠。
//
// 序列化與摘要不在這個檔案裡：那是 internal/canonical 的事（見 subject.go）。

// argString 取一個字串欄位；不是字串或空字串就回第一個非空的 fallback。
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

// argBool 取一個布林欄位。**只有真正的 true 算 true** —— 跟 canonical.mjs 的
// `args.sandbox === true` 一致，否則兩邊算出來的 subject 會不一樣。
func argBool(args map[string]any, key string) bool {
	v, _ := args[key].(bool)
	return v
}

// argObject 取一個物件欄位。陣列與 null 都不算物件（跟 canonical.mjs 的
// `typeof === "object" && !Array.isArray` 一致）。
func argObject(args map[string]any, key string) map[string]any {
	v, ok := args[key].(map[string]any)
	if !ok {
		return nil
	}
	return v
}

// argStringMap 把一個物件欄位轉成 map[string]string。
//
// 值的轉換照 canonical.mjs 的 `String(val)`：**兩邊要算出同一個 subject**，
// 所以數字與布林值要變成 JS 會變成的那個字串，不能靜靜丟掉（丟掉的症狀是
// payload_mismatch，一個看起來像「票壞了」的錯誤）。物件與 null 這裡不收 ——
// JS 會把它們變成 "[object Object]"／"null"，而那種東西出現在環境變數裡，
// 本身就是一個該被拒絕的請求。
func argStringMap(args map[string]any, key string) map[string]string {
	raw := argObject(args, key)
	if raw == nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
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
