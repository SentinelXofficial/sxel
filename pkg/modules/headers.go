package modules

import (
	"github.com/SentinelXofficial/sxel/pkg/payload"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var testHeaders = []string{
	"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
	"X-Real-IP", "Client-IP", "True-Client-IP", "CF-Connecting-IP",
	"X-Original-URL", "X-Rewrite-URL", "Via", "Forwarded",
}

// ScanHeaderInjection tests HTTP headers as SQLi/XSS injection points
func ScanHeaderInjection(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	limit := 15
	if len(payload.SQLiPayloads) < limit {
		limit = len(payload.SQLiPayloads)
	}

	for _, hdr := range testHeaders {
		// SQLi in headers
	HdrSQLiLoop:
		for _, base := range payload.SQLiPayloads[:limit] {
			variants := []string{base}
			if cfg.WAFBypass {
				variants = WAFBypassSQL(base)
			}
			for _, p := range variants {
				req, err := http.NewRequest("GET", target.URL, nil)
				if err != nil {
					continue
				}
				core.ApplyHeaders(req, cfg)
				req.Header.Set(hdr, p)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				b := core.ReadBody(resp.Body)
				resp.Body.Close()
				if ev := DetectSQLi(string(b)); ev != "" {
					results = append(results, core.ScanResult{
						Type: "SQL Injection via HTTP Header", URL: target.URL,
						Method: "GET", Parameter: hdr, Payload: p,
						Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
					})
					fmt.Printf("  [HDR-SQLI] header=%s payload=%q\n", hdr, p)
					break HdrSQLiLoop
				}
			}
		}

		// XSS in headers
		xcap := 12
		if len(payload.XSSPayloads) < xcap {
			xcap = len(payload.XSSPayloads)
		}
	HdrXSSLoop:
		for _, base := range payload.XSSPayloads[:xcap] {
			req, err := http.NewRequest("GET", target.URL, nil)
			if err != nil {
				continue
			}
			core.ApplyHeaders(req, cfg)
			req.Header.Set(hdr, base)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			b := core.ReadBody(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(b), base) {
				results = append(results, core.ScanResult{
					Type: "XSS via HTTP Header", URL: target.URL,
					Method: "GET", Parameter: hdr, Payload: base,
					Severity: "MEDIUM", Evidence: "payload reflected from header",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [HDR-XSS] header=%s payload=%q\n", hdr, base)
				break HdrXSSLoop
			}
		}
	}
	return results
}

// ScanCookieInjection tests each cookie value as injection point
func ScanCookieInjection(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	req0, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		return results
	}
	core.ApplyHeaders(req0, cfg)
	resp0, err := client.Do(req0)
	if err != nil {
		return results
	}
	resp0.Body.Close()
	cookies := resp0.Cookies()
	if len(cookies) == 0 {
		return results
	}

	limit := 12
	if len(payload.SQLiPayloads) < limit {
		limit = len(payload.SQLiPayloads)
	}

	for _, ck := range cookies {
	CookieSQLiLoop:
		for _, p := range payload.SQLiPayloads[:limit] {
			req, err := http.NewRequest("GET", target.URL, nil)
			if err != nil {
				continue
			}
			core.ApplyHeaders(req, cfg)
			for _, c := range cookies {
				if c.Name == ck.Name {
					req.AddCookie(&http.Cookie{Name: ck.Name, Value: p})
				} else {
					req.AddCookie(c)
				}
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			b := core.ReadBody(resp.Body)
			resp.Body.Close()
			if ev := DetectSQLi(string(b)); ev != "" {
				results = append(results, core.ScanResult{
					Type: "SQL Injection via Cookie", URL: target.URL,
					Method: "GET", Parameter: ck.Name, Payload: p,
					Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
				})
				fmt.Printf("  [COOKIE-SQLI] cookie=%s\n", ck.Name)
				break CookieSQLiLoop
			}
		}
	}

	// ── User-supplied cookie injection ──────────────────────────────────
	// Test cookies provided via --cookie flag, as these are likely the
	// cookies the application actually reads (session tokens, etc.).
	if cfg.Cookie != "" {
		xcap := 8
		if len(payload.XSSPayloads) < xcap {
			xcap = len(payload.XSSPayloads)
		}

		for _, part := range strings.Split(cfg.Cookie, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			ckName := strings.TrimSpace(kv[0])

			// ── SQLi in user cookies ──────────────────────────────────
		UserCookieSQLiLoop:
			for _, p := range payload.SQLiPayloads[:limit] {
				req, err := http.NewRequest("GET", target.URL, nil)
				if err != nil {
					continue
				}
				core.ApplyHeaders(req, cfg)
				req.Header.Set("Cookie", injectCookiePayload(cfg.Cookie, ckName, p))
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				b := core.ReadBody(resp.Body)
				resp.Body.Close()
				if ev := DetectSQLi(string(b)); ev != "" {
					results = append(results, core.ScanResult{
						Type: "SQL Injection via Cookie", URL: target.URL,
						Method: "GET", Parameter: ckName, Payload: p,
						Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
					})
					fmt.Printf("  [COOKIE-SQLI] user-cookie=%s\n", ckName)
					break UserCookieSQLiLoop
				}
			}

			// ── XSS in user cookies ───────────────────────────────────
		UserCookieXSSLoop:
			for _, p := range payload.XSSPayloads[:xcap] {
				req, err := http.NewRequest("GET", target.URL, nil)
				if err != nil {
					continue
				}
				core.ApplyHeaders(req, cfg)
				req.Header.Set("Cookie", injectCookiePayload(cfg.Cookie, ckName, p))
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				b := core.ReadBody(resp.Body)
				resp.Body.Close()
				if strings.Contains(string(b), p) {
					results = append(results, core.ScanResult{
						Type: "XSS via Cookie", URL: target.URL,
						Method: "GET", Parameter: ckName, Payload: p,
						Severity: "MEDIUM", Evidence: "payload reflected from user cookie",
						Timestamp: time.Now(),
					})
					fmt.Printf("  [COOKIE-XSS] user-cookie=%s\n", ckName)
					break UserCookieXSSLoop
				}
			}
		}
	}

	return results
}

// injectCookiePayload replaces the value of a named cookie in a Cookie header
// string with the given payload. Used to test user-supplied cookies for SQLi.
func injectCookiePayload(cookieHeader, targetName, payload string) string {
	var parts []string
	for _, part := range strings.Split(cookieHeader, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), targetName) {
			parts = append(parts, strings.TrimSpace(kv[0])+"="+payload)
		} else {
			parts = append(parts, strings.TrimSpace(part))
		}
	}
	return strings.Join(parts, "; ")
}

// CheckSecurityHeaders audits response headers for missing security controls
func CheckSecurityHeaders(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return results
	}
	core.ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	io.ReadAll(resp.Body) //nolint:errcheck
	resp.Body.Close()

	type check struct {
		name string
		sev  string
		fn   func() string
	}
	checks := []check{
		{"Strict-Transport-Security", "MEDIUM", func() string {
			if resp.Header.Get("Strict-Transport-Security") == "" {
				return "HSTS missing - downgrade attacks possible"
			}
			return ""
		}},
		{"Content-Security-Policy", "MEDIUM", func() string {
			if resp.Header.Get("Content-Security-Policy") == "" {
				return "CSP missing - XSS mitigations absent"
			}
			return ""
		}},
		{"X-Frame-Options", "MEDIUM", func() string {
			v := resp.Header.Get("X-Frame-Options")
			if v == "" {
				return "X-Frame-Options missing - clickjacking risk"
			}
			return ""
		}},
		{"X-Content-Type-Options", "LOW", func() string {
			if resp.Header.Get("X-Content-Type-Options") == "" {
				return "X-Content-Type-Options missing - MIME sniffing risk"
			}
			return ""
		}},
		{"Referrer-Policy", "LOW", func() string {
			if resp.Header.Get("Referrer-Policy") == "" {
				return "Referrer-Policy missing - URL leakage risk"
			}
			return ""
		}},
		{"Permissions-Policy", "LOW", func() string {
			if resp.Header.Get("Permissions-Policy") == "" {
				return "Permissions-Policy missing"
			}
			return ""
		}},
		{"Server", "INFO", func() string {
			v := resp.Header.Get("Server")
			if v != "" {
				return fmt.Sprintf("Server banner discloses: %q", v)
			}
			return ""
		}},
		{"X-Powered-By", "INFO", func() string {
			v := resp.Header.Get("X-Powered-By")
			if v != "" {
				return fmt.Sprintf("X-Powered-By discloses: %q", v)
			}
			return ""
		}},
		{"X-AspNet-Version", "INFO", func() string {
			v := resp.Header.Get("X-AspNet-Version")
			if v != "" {
				return fmt.Sprintf("ASP.NET version disclosed: %q", v)
			}
			return ""
		}},
	}

	for _, c := range checks {
		if ev := c.fn(); ev != "" {
			results = append(results, core.ScanResult{
				Type: "Security Header Issue", URL: targetURL,
				Method: "GET", Parameter: c.name, Payload: "-",
				Severity: c.sev, Evidence: ev, Timestamp: time.Now(),
			})
		}
	}
	return results
}

// CheckCORS tests for CORS misconfiguration
// CheckCORS tests for CORS misconfiguration including preflight and private network access.
func CheckCORS(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult

	targetParsed, err := url.Parse(targetURL)
	if err != nil {
		return results
	}
	origins := []string{"https://evil.com", "null", "https://evil." + targetParsed.Host}
	for _, origin := range origins {
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(req, cfg)
		req.Header.Set("Origin", origin)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.ReadAll(resp.Body) //nolint:errcheck
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

		if acao == "*" {
			results = append(results, core.ScanResult{
				Type: "CORS Misconfiguration (Wildcard)", URL: targetURL,
				Method: "GET", Parameter: "Origin", Payload: origin,
				Severity: "MEDIUM",
				Evidence:  "Access-Control-Allow-Origin: *",
				Timestamp: time.Now(),
			})
			fmt.Printf("  [CORS] wildcard ACAO at %s\n", targetURL)
		} else if acao == origin {
			sev := "MEDIUM"
			ev := fmt.Sprintf("ACAO reflects arbitrary origin: %s", acao)
			if acac == "true" {
				sev = "HIGH"
				ev += " + ACAC: true (credentials allowed)"
			}
			results = append(results, core.ScanResult{
				Type: "CORS Misconfiguration (Origin Reflection)", URL: targetURL,
				Method: "GET", Parameter: "Origin", Payload: origin,
				Severity: sev, Evidence: ev, Timestamp: time.Now(),
			})
			fmt.Printf("  [CORS] origin reflection creds=%s at %s\n", acac, targetURL)
		}
	}

	// ── Extended CORS: Preflight (OPTIONS) ─────────────────────────────
	preflightReq, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err == nil {
		core.ApplyHeaders(preflightReq, cfg)
		preflightReq.Header.Set("Origin", "https://evil.com")
		preflightReq.Header.Set("Access-Control-Request-Method", "GET")
		preflightReq.Header.Set("Access-Control-Request-Headers", "X-Custom-Auth")
		preResp, pErr := client.Do(preflightReq)
		if pErr == nil {
			io.ReadAll(preResp.Body) //nolint:errcheck
			preResp.Body.Close()
			if preResp.StatusCode >= 200 && preResp.StatusCode < 400 {
				allowOrigin := preResp.Header.Get("Access-Control-Allow-Origin")
				if allowOrigin == "https://evil.com" || allowOrigin == "*" {
					allowMethods := preResp.Header.Get("Access-Control-Allow-Methods")
					allowHeaders := preResp.Header.Get("Access-Control-Allow-Headers")
					acacPre := strings.ToLower(preResp.Header.Get("Access-Control-Allow-Credentials"))
					sevPre := "MEDIUM"
					evPre := fmt.Sprintf("Preflight accepted: Origin=%s", allowOrigin)
					if acacPre == "true" {
						sevPre = "HIGH"
						evPre += " with ACAC: true"
					}
					if allowMethods != "" {
						evPre += " Methods: " + allowMethods
					}
					if allowHeaders != "" {
						evPre += " Headers: " + allowHeaders
					}
					results = append(results, core.ScanResult{
						Type: "CORS — Preflight Accepted (Extended)", URL: targetURL,
						Method: "OPTIONS", Parameter: "Origin + Request-Method",
						Payload: "Origin: https://evil.com; ACM: GET; ACH: X-Custom-Auth",
						Severity: sevPre, Evidence: evPre, Timestamp: time.Now(),
					})
					fmt.Printf("  [CORS-EXT] preflight accepted at %s (%s)\n", targetURL, sevPre)
				}
			}
		}
	}

	// ── Extended CORS: Private Network Access ──────────────────────────
	privReq, err := http.NewRequest("GET", targetURL, nil)
	if err == nil {
		core.ApplyHeaders(privReq, cfg)
		privReq.Header.Set("Origin", "https://evil.com")
		privReq.Header.Set("Access-Control-Request-Private-Network", "true")
		privResp, prErr := client.Do(privReq)
		if prErr == nil {
			allowPrivate := privResp.Header.Get("Access-Control-Allow-Private-Network")
			io.ReadAll(privResp.Body) //nolint:errcheck
			privResp.Body.Close()
			if allowPrivate == "true" {
				results = append(results, core.ScanResult{
					Type: "CORS — Private Network Access Allowed", URL: targetURL,
					Method: "GET", Parameter: "Origin",
					Payload: "Access-Control-Request-Private-Network: true",
					Severity: "HIGH",
					Evidence: "Access-Control-Allow-Private-Network: true — allows requests from private network contexts",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [CORS-EXT] private network access allowed at %s\n", targetURL)
			}
		}
	}

	return results
}

// CheckHTTPMethods tests which HTTP methods the server accepts
func CheckHTTPMethods(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult
	for _, method := range []string{"PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "CONNECT"} {
		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(req, cfg)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.ReadAll(resp.Body) //nolint:errcheck
		resp.Body.Close()

		// Only flag as "allowed" on success or redirect; 4xx means blocked/unauthorised
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			sev := "LOW"
			if method == "PUT" || method == "DELETE" || method == "TRACE" {
				sev = "MEDIUM"
			}
			results = append(results, core.ScanResult{
				Type: "Dangerous HTTP Method Allowed", URL: targetURL,
				Method: method, Parameter: "method", Payload: method,
				Severity: sev,
				Evidence:  fmt.Sprintf("HTTP %d returned for %s", resp.StatusCode, method),
				Timestamp: time.Now(),
			})
			fmt.Printf("  [HTTP-METHOD] %s allowed at %s HTTP=%d\n", method, targetURL, resp.StatusCode)
		}
	}
	return results
}

// ScanHostHeaderInjection tests Host header for injection/cache poisoning
func ScanHostHeaderInjection(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult
	evil := "evil.com"
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return results
	}
	core.ApplyHeaders(req, cfg)
	req.Host = evil
	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	b := core.ReadBody(resp.Body)
	resp.Body.Close()

	body := string(b)
	if strings.Contains(body, evil) || strings.Contains(resp.Header.Get("Location"), evil) {
		results = append(results, core.ScanResult{
			Type: "Host Header Injection", URL: targetURL,
			Method: "GET", Parameter: "Host", Payload: evil,
			Severity: "MEDIUM",
			Evidence:  "injected Host value reflected in response or redirect",
			Timestamp: time.Now(),
		})
		fmt.Printf("  [HOST-INJECT] reflection at %s\n", targetURL)
		}
	return results
}

// ScanCRLFInjection tests for CRLF header injection
func ScanCRLFInjection(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	crlfPayloads := []string{
		"%0d%0aX-Injected: evil",
		"%0aX-Injected: evil",
		"\r\nX-Injected: evil",
		"%0d%0a%20X-Injected: evil",
		"foo%0d%0aX-Injected: evil",
	}

	p, _ := url.Parse(target.URL)
	params, _ := url.ParseQuery(p.RawQuery)

	for param := range params {
		for _, payload := range crlfPayloads {
			testURL, err := core.SetParam(target.URL, param, payload)
			if err != nil {
				continue
			}
			noRedir := &http.Client{
				Timeout:   client.Timeout,
				Transport: client.Transport,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			core.ApplyHeaders(req, cfg)
			resp, err := noRedir.Do(req)
			if err != nil {
				continue
			}
			io.ReadAll(resp.Body) //nolint:errcheck
			resp.Body.Close()

			if resp.Header.Get("X-Injected") != "" {
				results = append(results, core.ScanResult{
					Type: "CRLF Injection / Header Injection", URL: testURL,
					Method: "GET", Parameter: param, Payload: payload,
					Severity: "HIGH",
					Evidence:  "injected header X-Injected found in response",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [CRLF] param=%s payload=%q\n", param, payload)
				break
			}
		}
	}
	return results
}

