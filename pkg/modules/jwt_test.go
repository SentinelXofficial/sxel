package modules

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func testToken(t *testing.T) (header, payload, sig, token string) {
	t.Helper()
	header = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"Test User","iat":1516239022}`))
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(header + "." + payload))
	sig = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return header, payload, sig, buildJWT(header, payload, sig)
}

func TestIsJWT(t *testing.T) {
	_, _, _, token := testToken(t)

	nonJSONHeader := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	undecodable := "!!!not-base64!!!"

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid HS256 token", token, true},
		{"empty string", "", false},
		{"garbage", "this-is-not-a-token", false},
		{"two segments", "aaaa.bbbb", false},
		{"four segments", "aaaa.bbbb.cccc.dddd", false},
		{"header not JSON", nonJSONHeader + ".payload.sig", false},
		{"undecodable segment", undecodable + ".payload.sig", false},
		{"empty header", ".payload.sig", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isJWT(tt.input); got != tt.want {
				t.Errorf("isJWT(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSplitJWT(t *testing.T) {
	header, payload, sig, token := testToken(t)

	h, p, s, ok := splitJWT(token)
	if !ok {
		t.Fatal("splitJWT returned ok=false for a valid token")
	}
	if h != header || p != payload || s != sig {
		t.Errorf("splitJWT mismatch:\n got (%q, %q, %q)\nwant (%q, %q, %q)", h, p, s, header, payload, sig)
	}

	if _, _, _, ok := splitJWT("only.two"); ok {
		t.Error("splitJWT on a 2-segment string should return ok=false")
	}
}

func TestJWTHeaderAlg(t *testing.T) {
	headerB64, _, _, _ := testToken(t)

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"proper token header", headerB64, "HS256"},
		{"undecodable header", "!!!not-base64!!!", "unknown"},
		{"decodes but not JSON", base64.RawURLEncoding.EncodeToString([]byte("hello")), "unknown"},
		{"JSON without alg", base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`)), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jwtHeaderAlg(tt.header); got != tt.want {
				t.Errorf("jwtHeaderAlg(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestJWTSetAlg(t *testing.T) {
	headerB64, _, _, _ := testToken(t)

	changed := jwtSetAlg(headerB64, "none")
	if changed == headerB64 {
		t.Fatal("jwtSetAlg returned the original header")
	}

	data, ok := decodeJWTPart(changed)
	if !ok {
		t.Fatalf("jwtSetAlg output does not decode: %q", changed)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("jwtSetAlg output is not valid JSON: %v", err)
	}
	if alg, _ := m["alg"].(string); alg != "none" {
		t.Errorf("expected alg %q, got %q", "none", alg)
	}
	if typ, _ := m["typ"].(string); typ != "JWT" {
		t.Errorf("expected typ %q preserved, got %q", "JWT", typ)
	}

	if got := jwtSetAlg("garbage!!", "none"); got != "garbage!!" {
		t.Errorf("jwtSetAlg on undecodable header = %q, want original", got)
	}
}

func TestDecodeJWTPart(t *testing.T) {
	plain := []byte(`{"sub":"1234567890","exp":1937897400}`)

	tests := []struct {
		name string
		enc  func([]byte) string
	}{
		{"raw base64url", base64.RawURLEncoding.EncodeToString},
		{"padded base64url", base64.URLEncoding.EncodeToString},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := decodeJWTPart(tt.enc(plain))
			if !ok {
				t.Fatal("decodeJWTPart returned ok=false")
			}
			if string(got) != string(plain) {
				t.Errorf("decodeJWTPart = %q, want %q", string(got), string(plain))
			}
		})
	}

	if _, ok := decodeJWTPart("###"); ok {
		t.Error("decodeJWTPart should fail on undecodable input")
	}
}

func TestBuildJWTRoundTrip(t *testing.T) {
	header, payload, sig, token := testToken(t)
	if token != header+"."+payload+"."+sig {
		t.Errorf("buildJWT assembled token %q, want %q", token, header+"."+payload+"."+sig)
	}

	h, p, s, ok := splitJWT(token)
	if !ok || h != header || p != payload || s != sig {
		t.Errorf("round trip failed: got (%q, %q, %q, %v)", h, p, s, ok)
	}

	unsigned := buildJWT(header, payload, "")
	if unsigned != header+"."+payload+"." {
		t.Errorf("buildJWT with empty sig = %q", unsigned)
	}
}

func TestExtractBearer(t *testing.T) {
	tests := []struct {
		name  string
		input string
		token string
		ok    bool
	}{
		{"bearer prefix", "Bearer eyJhbGciOiJIUzI1NiJ9", "eyJhbGciOiJIUzI1NiJ9", true},
		{"lowercase prefix", "bearer abc.def.ghi", "abc.def.ghi", true},
		{"no bearer prefix", "Basic dXNlcjpwYXNz", "", false},
		{"empty value", "Bearer ", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, ok := extractBearer(tt.input)
			if tok != tt.token || ok != tt.ok {
				t.Errorf("extractBearer(%q) = (%q, %v), want (%q, %v)", tt.input, tok, ok, tt.token, tt.ok)
			}
		})
	}
}

func testRSAKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &key.PublicKey
}

func TestJwkModulusBytes(t *testing.T) {
	mod := []byte{0x00, 0xb8, 0x7a, 0x99, 0xff}

	tests := []struct {
		name string
		enc  func([]byte) string
	}{
		{"raw base64url", base64.RawURLEncoding.EncodeToString},
		{"padded base64url", base64.URLEncoding.EncodeToString},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := jwkModulusBytes(tt.enc(mod))
			if !ok {
				t.Fatal("jwkModulusBytes returned ok=false")
			}
			if string(got) != string(mod) {
				t.Errorf("jwkModulusBytes = %x, want %x", got, mod)
			}
		})
	}

	if _, ok := jwkModulusBytes("###not-base64###"); ok {
		t.Error("jwkModulusBytes should fail on undecodable input")
	}
}

func TestJwkExponent(t *testing.T) {
	e65537 := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01})

	tests := []struct {
		name  string
		input string
		want  int
		ok    bool
	}{
		{"AQAB", e65537, 65537, true},
		{"standard exponent", base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}), 65537, true},
		{"undecodable", "!!!", 0, false},
		{"zero exponent", "AA==", 0, false},
		{"absurdly large exponent", "f////////////////8B", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := jwkExponent(tt.input)
			if got != tt.want || ok != tt.ok {
				t.Errorf("jwkExponent(%q) = (%d, %v), want (%d, %v)", tt.input, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestJwkToRSAPublicKeyPEM(t *testing.T) {
	pub := testRSAKey(t)

	pemKey := jwkToRSAPublicKeyPEM(pub.N.Bytes(), pub.E)
	if !strings.Contains(pemKey, "BEGIN RSA PUBLIC KEY") || !strings.Contains(pemKey, "END RSA PUBLIC KEY") {
		t.Fatalf("expected PEM block, got %q", pemKey)
	}

	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		t.Fatal("pem.Decode failed on jwkToRSAPublicKeyPEM output")
	}
	parsed, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKCS1PublicKey: %v", err)
	}
	if parsed.E != pub.E {
		t.Errorf("exponent mismatch: got %d, want %d", parsed.E, pub.E)
	}
	if parsed.N.Cmp(pub.N) != 0 {
		t.Errorf("modulus mismatch: got %x, want %x", parsed.N.Bytes(), pub.N.Bytes())
	}
}

func TestParseJWKS(t *testing.T) {
	pub := testRSAKey(t)
	nB64 := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01})

	t.Run("valid RSA key set", func(t *testing.T) {
		body := `{"keys":[{"kty":"RSA","kid":"test-key","n":"` + nB64 + `","e":"` + eB64 + `"}]}`
		pemKey, kid, modulus, ok := parseJWKS(body)
		if !ok {
			t.Fatal("parseJWKS returned ok=false for a valid key set")
		}
		if kid != "test-key" {
			t.Errorf("kid = %q, want %q", kid, "test-key")
		}
		if string(modulus) != string(pub.N.Bytes()) {
			t.Errorf("modulus mismatch: got %x, want %x", modulus, pub.N.Bytes())
		}
		if !strings.Contains(pemKey, "RSA PUBLIC KEY") {
			t.Errorf("expected RSA PUBLIC KEY PEM, got %q", pemKey)
		}
	})

	t.Run("skips non-RSA keys", func(t *testing.T) {
		body := `{"keys":[{"kty":"EC","kid":"ec-key","n":"` + nB64 + `","e":"` + eB64 + `"}]}`
		if _, _, _, ok := parseJWKS(body); ok {
			t.Error("parseJWKS should skip EC keys")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		if _, _, _, ok := parseJWKS("not json"); ok {
			t.Error("parseJWKS should fail on invalid JSON")
		}
	})

	t.Run("missing fields", func(t *testing.T) {
		body := `{"keys":[{"kty":"RSA","kid":"k","e":"` + eB64 + `"}]}`
		if _, _, _, ok := parseJWKS(body); ok {
			t.Error("parseJWKS should reject a key without a modulus")
		}
	})
}

func TestTamperJWTSignature(t *testing.T) {
	_, _, sig, token := testToken(t)

	tampered := tamperJWTSignature(sig)
	if tampered == sig {
		t.Error("tamperJWTSignature returned the original signature")
	}
	if len(tampered) != len(sig) {
		t.Errorf("tampered signature length %d, want %d", len(tampered), len(sig))
	}

	header, payload, _, _ := splitJWT(token)
	if !isJWT(buildJWT(header, payload, tampered)) {
		t.Error("tampered token should still be parseable as a JWT")
	}

	if got := tamperJWTSignature(""); got != "x" {
		t.Errorf("tamperJWTSignature(\"\") = %q, want %q", got, "x")
	}
}

func TestMedianDuration(t *testing.T) {
	tests := []struct {
		name string
		in   []time.Duration
		want time.Duration
	}{
		{"odd count", []time.Duration{30, 10, 20}, 20},
		{"even count", []time.Duration{40, 10, 30, 20}, 30},
		{"unsorted input", []time.Duration{5, 3, 4}, 4},
		{"empty", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := medianDuration(tt.in); got != tt.want {
				t.Errorf("medianDuration(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
