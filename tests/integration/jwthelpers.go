package integration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func buildTestJWT(secret string) string {
	header := b64url([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := b64url([]byte(`{"sub":"1234567890","role":"admin"}`))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + b64url(mac.Sum(nil))
}

func jwtVerifyHS256(token, secret string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	return hmac.Equal(mac.Sum(nil), sig)
}

func jwtHeaderField(headerB64, field string) string {
	data, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return ""
	}
	var m map[string]interface{}
	if json.Unmarshal(data, &m) != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	return ""
}
