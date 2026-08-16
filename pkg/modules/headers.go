package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/payload"
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

func ScanHeaderInjection(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	limit := 15
	if len(payload.SQLiPayloads) < limit {
		limit = len(payload.SQLiPayloads)
	}

	for _, hdr := range testHeaders {
		baseBody := headerSQLiBaseline(client, cfg, target.URL, hdr)
		if baseBody == "" || DetectSQLi(baseBody) != "" {
			continue
		}
	HdrSQLiLoop:
		for _, base := range payload.SQLiPayloads[:limit] {
			variants := []string{base}
			if cfg.WAFBypass {
				variants = WAFBypassSQL(base)
			}
			for _, p := range variants {
				if headerSQLiControl(client, cfg, target.URL, p) {
					continue
				}
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

		xcap := 12
		if len(payload.XSSPayloads) < xcap {
			xcap = len(payload.XSSPayloads)
		}
		baseReq, err := http.NewRequest("GET", target.URL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(baseReq, cfg)
		baseReq.Header.Set(hdr, "sxhdrx_baseline_marker")
		baseResp, err := client.Do(baseReq)
		baseBody = ""
		if err == nil {
			baseBody = core.ReadBody(baseResp.Body)
			baseResp.Body.Close()
		}
	HdrXSSLoop:
		for _, base := range payload.XSSPayloads[:xcap] {
			if strings.Contains(baseBody, base) {
				continue
			}
			ctrlReq, err := http.NewRequest("GET", target.URL, nil)
			if err != nil {
				continue
			}
			core.ApplyHeaders(ctrlReq, cfg)
			ctrlReq.Header.Set("X-Sxel-Contr", base)
			ctrlResp, err := client.Do(ctrlReq)
			ctrlBody := ""
			if err == nil {
				ctrlBody = core.ReadBody(ctrlResp.Body)
				ctrlResp.Body.Close()
			}
			if strings.Contains(ctrlBody, base) {
				continue
			}
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
	baseBody := core.ReadBody(resp0.Body)
	resp0.Body.Close()
	if DetectSQLi(baseBody) != "" {
		return results
	}
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
			if headerSQLiControl(client, cfg, target.URL, p) {
				continue
			}
			req, err := http.NewRequest("GET", target.URL, nil)
			if err != nil {
				continue
			}
			core.ApplyHeaders(req, cfg)
			req.Header.Set("Cookie", rebuildCookieHeader(cfg.Cookie, cookies, ck.Name, p))
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

		UserCookieSQLiLoop:
			for _, p := range payload.SQLiPayloads[:limit] {
				if headerSQLiControl(client, cfg, target.URL, p) {
					continue
				}
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

			baseBody := ""
			if breq, berr := http.NewRequest("GET", target.URL, nil); berr == nil {
				core.ApplyHeaders(breq, cfg)
				breq.Header.Set("Cookie", cfg.Cookie)
				if bresp, e := client.Do(breq); e == nil {
					baseBody = core.ReadBody(bresp.Body)
					bresp.Body.Close()
				}
			}
		UserCookieXSSLoop:
			for _, p := range payload.XSSPayloads[:xcap] {
				if strings.Contains(baseBody, p) {
					continue
				}
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

func headerSQLiBaseline(client *http.Client, cfg *core.Config, targetURL, hdr string) string {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return ""
	}
	core.ApplyHeaders(req, cfg)
	req.Header.Set(hdr, "sxhdrx_baseline_marker")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	body := core.ReadBody(resp.Body)
	resp.Body.Close()
	return string(body)
}

func headerSQLiControl(client *http.Client, cfg *core.Config, targetURL, payload string) bool {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}
	core.ApplyHeaders(req, cfg)
	req.Header.Set("X-Sxel-Contr", payload)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body := core.ReadBody(resp.Body)
	resp.Body.Close()
	return DetectSQLi(string(body)) != ""
}

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

func rebuildCookieHeader(cfgCookie string, serverCookies []*http.Cookie, targetName, payload string) string {
	type kv struct{ name, value string }
	var pairs []kv
	if cfgCookie != "" {
		for _, part := range strings.Split(cfgCookie, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, value, _ := strings.Cut(part, "=")
			pairs = append(pairs, kv{strings.TrimSpace(name), value})
		}
	}
	for _, c := range serverCookies {
		pairs = append(pairs, kv{c.Name, c.Value})
	}
	injected := false
	var parts []string
	for _, pr := range pairs {
		if strings.EqualFold(pr.name, targetName) {
			if !injected {
				parts = append(parts, pr.name+"="+payload)
				injected = true
			}
			continue
		}
		parts = append(parts, pr.name+"="+pr.value)
	}
	if !injected {
		parts = append(parts, targetName+"="+payload)
	}
	return strings.Join(parts, "; ")
}

func originIsSubdomainOf(originURL, targetHost string) bool {
	u, err := url.Parse(originURL)
	if err != nil {
		return false
	}
	oh := strings.ToLower(u.Hostname())
	th := strings.ToLower(targetHost)
	return oh != th && strings.HasSuffix(oh, "."+th)
}

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
	core.ReadBody(resp.Body)
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

func CheckCORS(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult

	targetParsed, err := url.Parse(targetURL)
	if err != nil {
		return results
	}
	origins := []string{"https://evil.com", "null", "https://attacker.example"}
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
		core.ReadBody(resp.Body)
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

		if acao == "*" {
			results = append(results, core.ScanResult{
				Type: "CORS Misconfiguration (Wildcard)", URL: targetURL,
				Method: "GET", Parameter: "Origin", Payload: origin,
				Severity:  "MEDIUM",
				Evidence:  "Access-Control-Allow-Origin: *",
				Timestamp: time.Now(),
			})
			fmt.Printf("  [CORS] wildcard ACAO at %s\n", targetURL)
		} else if acao == origin {
			if originIsSubdomainOf(origin, targetParsed.Hostname()) {
				continue
			}
			sev := "LOW"
			ev := fmt.Sprintf("ACAO reflects unrelated origin: %s", acao)
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

	preflightReq, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err == nil {
		core.ApplyHeaders(preflightReq, cfg)
		preflightReq.Header.Set("Origin", "https://evil.com")
		preflightReq.Header.Set("Access-Control-Request-Method", "GET")
		preflightReq.Header.Set("Access-Control-Request-Headers", "X-Custom-Auth")
		preResp, pErr := client.Do(preflightReq)
		if pErr == nil {
			core.ReadBody(preResp.Body)
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
						Payload:  "Origin: https://evil.com; ACM: GET; ACH: X-Custom-Auth",
						Severity: sevPre, Evidence: evPre, Timestamp: time.Now(),
					})
					fmt.Printf("  [CORS-EXT] preflight accepted at %s (%s)\n", targetURL, sevPre)
				}
			}
		}
	}

	privReq, err := http.NewRequest("GET", targetURL, nil)
	if err == nil {
		core.ApplyHeaders(privReq, cfg)
		privReq.Header.Set("Origin", "https://evil.com")
		privReq.Header.Set("Access-Control-Request-Private-Network", "true")
		privResp, prErr := client.Do(privReq)
		if prErr == nil {
			allowPrivate := privResp.Header.Get("Access-Control-Allow-Private-Network")
			core.ReadBody(privResp.Body)
			privResp.Body.Close()
			if allowPrivate == "true" {
				results = append(results, core.ScanResult{
					Type: "CORS — Private Network Access Allowed", URL: targetURL,
					Method: "GET", Parameter: "Origin",
					Payload:   "Access-Control-Request-Private-Network: true",
					Severity:  "HIGH",
					Evidence:  "Access-Control-Allow-Private-Network: true — allows requests from private network contexts",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [CORS-EXT] private network access allowed at %s\n", targetURL)
			}
		}
	}

	return results
}

func CheckHTTPMethods(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult
	for _, method := range []string{"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"} {
		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(req, cfg)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		core.ReadBody(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			sev := "LOW"
			if method == "PUT" || method == "DELETE" || method == "TRACE" {
				sev = "MEDIUM"
			}
			results = append(results, core.ScanResult{
				Type: "Dangerous HTTP Method Allowed", URL: targetURL,
				Method: method, Parameter: "method", Payload: method,
				Severity:  sev,
				Evidence:  fmt.Sprintf("HTTP %d returned for %s", resp.StatusCode, method),
				Timestamp: time.Now(),
			})
			fmt.Printf("  [HTTP-METHOD] %s allowed at %s HTTP=%d\n", method, targetURL, resp.StatusCode)
		}
	}
	return results
}

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
			Severity:  "MEDIUM",
			Evidence:  "injected Host value reflected in response or redirect",
			Timestamp: time.Now(),
		})
		fmt.Printf("  [HOST-INJECT] reflection at %s\n", targetURL)
	}
	return results
}

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

	noRedir := &http.Client{
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for param := range params {
		for _, payload := range crlfPayloads {
			testURL, err := core.SetParamRaw(target.URL, param, payload)
			if err != nil {
				continue
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
			core.ReadBody(resp.Body)
			resp.Body.Close()

			if resp.Header.Get("X-Injected") != "" {
				results = append(results, core.ScanResult{
					Type: "CRLF Injection / Header Injection", URL: testURL,
					Method: "GET", Parameter: param, Payload: payload,
					Severity:  "HIGH",
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
