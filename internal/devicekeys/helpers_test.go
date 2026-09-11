package devicekeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"
)

// 一把假的 passkey。瀏覽器的 getPublicKey() 給的就是 SPKI，所以這裡也存 SPKI。
type testCred struct {
	id  string
	pub string
	key *ecdsa.PrivateKey
}

func newCred(t *testing.T, id string) testCred {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return testCred{id: id, pub: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), key: key}
}

// signs 模擬驗證器：簽 authenticatorData || sha256(clientDataJSON)。
func (c testCred) signs(t *testing.T, challenge string) Assertion {
	t.Helper()
	clientData, _ := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": challenge})
	authData := make([]byte, 37)
	authData[32] = 0x01 // UP：使用者真的在場
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return Assertion{
		CredentialID:      c.id,
		AuthenticatorData: b64urlEncode(authData),
		ClientDataJSON:    b64urlEncode(clientData),
		Signature:         b64urlEncode(sig),
	}
}

// enrollAdd / enrollRemove 是 encodeEnrollment 的測試版（app 那一側的事，
// 不屬於 daemon，所以只存在於測試裡）。
func enrollAdd(machineID string, c testCred, label string, now time.Time) string {
	return encodeEnroll(map[string]any{
		"v": 1, "op": "add", "machineId": machineID, "credentialId": c.id,
		"publicKey": c.pub, "label": nullable(label),
		"iat": now.UnixMilli(), "exp": now.Add(10 * time.Minute).UnixMilli(),
	})
}

func enrollRemove(machineID, credentialID string, now time.Time) string {
	return encodeEnroll(map[string]any{
		"v": 1, "op": "remove", "machineId": machineID, "credentialId": credentialID,
		"publicKey": nil, "label": nil,
		"iat": now.UnixMilli(), "exp": now.Add(10 * time.Minute).UnixMilli(),
	})
}

func encodeEnroll(body map[string]any) string {
	raw, _ := json.Marshal(body)
	return b64urlEncode(raw)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// deviceTicket 把一組 claims 與一次簽章包成線路上那個字串。
func deviceTicket(t *testing.T, c testCred, machineID, tool, payloadHash, invokeID string, now time.Time) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"v": 1, "alg": "webauthn", "invokeId": invokeID, "machineId": machineID,
		"tool": tool, "payloadHash": payloadHash, "scope": nil,
		"iat": now.UnixMilli(), "exp": now.Add(ApprovalTTL).UnixMilli(),
	})
	claimsB64 := b64urlEncode(raw)
	body, _ := json.Marshal(c.signs(t, ChallengeFor(claimsB64)))
	return TicketPrefix + claimsB64 + "." + b64urlEncode(body)
}
