package devicekeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// SignatureVerifier 是這個套件對「驗簽章」這件事唯一的需求，**刻意窄到只有
// 一個方法**。
//
// 為什麼是介面：驗證器那一層（authenticatorData 的解析、COSE 金鑰、attestation）
// 在這個 repo 裡有別的套件在做，而這個套件不想假設它存在、也不想在它改名的
// 時候一起壞掉。呼叫端注入即可；不注入就用 signature.go 裡的標準庫實作。
//
// 為什麼只窄到「驗簽章」而不是「驗整張 assertion」：challenge 綁定、UP bit、
// ceremony 型別這三條是這個方案的安全規則本身，它們必須留在這裡、被測試釘
// 住，而不是交給一個可以被抽換的東西決定。
type SignatureVerifier interface {
	// Verify 用一把 SPKI 公鑰（PEM）驗 message 上的 SHA-256 簽章。
	//
	// 回傳值刻意分成兩種，對應 TS 那邊 `createVerify("sha256").verify()` 的
	// 兩種結局：
	//   - err != nil     → 這把金鑰根本用不了（reason: bad_key，TS 是丟例外）
	//   - ok == false    → 金鑰沒問題，但簽章不對（reason: bad_signature）
	Verify(publicKeyPEM string, message, signature []byte) (ok bool, err error)
}

// StdSignatureVerifier 是預設實作：Go 標準庫，對齊 Node 的
// `createVerify("sha256")`。
//
// 支援 ECDSA（DER 編碼的簽章，Node 的預設 dsaEncoding）與 RSA PKCS#1 v1.5。
// Ed25519 一併回 bad_key —— 不是漏掉，是 Node 那邊 createVerify 對 Ed25519 會
// 丟 ERR_CRYPTO_UNSUPPORTED_OPERATION，兩邊要給同一個判斷。
type StdSignatureVerifier struct{}

var errUnsupportedKey = errors.New("devicekeys: 這種金鑰不能用 sha256 驗章")

func (StdSignatureVerifier) Verify(publicKeyPEM string, message, signature []byte) (bool, error) {
	key, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(message)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest[:], signature), nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], signature) == nil, nil
	default:
		return false, errUnsupportedKey
	}
}

// parsePublicKey 對應 Node 的 createPublicKey：SPKI 為主，順便收 PKCS#1 的
// RSA 公鑰（Node 也收）。
//
// 這支同時是 Store 存金鑰前的那道檢查：壞掉的金鑰存進去之後，症狀會是「使用者
// 按了同意卻被拒絕」，而那個訊息離真正的原因（註冊那一刻就錯了）隔了好幾天。
func parsePublicKey(pemText string) (any, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("devicekeys: 不是合法的 PEM")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("devicekeys: 這串不是一把公鑰")
}
