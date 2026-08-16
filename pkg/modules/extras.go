package modules

import (
	"encoding/json"
	"fmt"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/payload"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func redirectsToEvil(loc string) bool {
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "evil.com" || strings.HasSuffix(h, ".evil.com")
}

func ScanOpenRedirect(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	redirectPayloads := []string{
		"https://evil.com",
		"//evil.com",
		"/\\evil.com",
		"///evil.com",
		"https:evil.com",
		"/%09/evil.com",
		"//evil%2Ecom",
		"https://evil.com%2F%2F",
	}
	redirectParamHints := []string{
		"url", "redirect", "redirect_url", "return", "return_url",
		"target", "dest", "destination", "redir",
		"redirect_to", "goto", "link", "continue",
		"location", "forward", "callback",
	}

	noRedir := &http.Client{
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	p, _ := url.Parse(target.URL)
	params, _ := url.ParseQuery(p.RawQuery)

	for param := range params {
		lp := strings.ToLower(param)
		isHint := false
		for _, h := range redirectParamHints {
			if strings.Contains(lp, h) {
				isHint = true
				break
			}
		}
		if !isHint {
			continue
		}

	RedirectLoop:
		for _, payload := range redirectPayloads {
			testURL, _ := core.SetParam(target.URL, param, payload)
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

			loc := resp.Header.Get("Location")
			if resp.StatusCode >= 300 && resp.StatusCode < 400 &&
				(redirectsToEvil(loc) || strings.Contains(loc, payload)) {
				results = append(results, core.ScanResult{
					Type: "Open Redirect", URL: testURL,
					Method: "GET", Parameter: param, Payload: payload,
					Severity:  "MEDIUM",
					Evidence:  fmt.Sprintf("redirects to: %s (HTTP %d)", loc, resp.StatusCode),
					Timestamp: time.Now(),
				})
				fmt.Printf("  [OPEN-REDIRECT] param=%s -> %s\n", param, loc)
				break RedirectLoop
			}
		}
	}
	return results
}

func ScanPathTraversal(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	payloads := []string{
		"../../../../etc/passwd",
		"../../etc/passwd",
		"../../../etc/passwd",
		"../../../../etc/passwd%00",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"..%252F..%252Fetc%252Fpasswd",
		"....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2fetc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"../../../../windows/win.ini",
		"..%5c..%5cwindows%5cwin.ini",
	}

	p, _ := url.Parse(target.URL)
	params, _ := url.ParseQuery(p.RawQuery)

	for param := range params {
		safeURL, _ := core.SetParam(target.URL, param, "sxel_safe_baseline_0")
		baseline, _, baseErr := core.DoGET(client, cfg, safeURL)
		if baseErr != nil {
			continue
		}
	TraversalLoop:
		for _, payload := range payloads {
			testURL, err := core.SetParamRaw(target.URL, param, payload)
			if err != nil {
				continue
			}
			body, _, err := core.DoGET(client, cfg, testURL)
			if err != nil {
				continue
			}
			if pathTraversalHit(body) && !pathTraversalHit(baseline) {
				results = append(results, core.ScanResult{
					Type: "Path Traversal", URL: testURL,
					Method: "GET", Parameter: param, Payload: payload,
					Severity:  "HIGH",
					Evidence:  "system file content found in response (/etc/passwd or win.ini)",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [PATH-TRAVERSAL] param=%s payload=%q\n", param, payload)
				break TraversalLoop
			}
		}
	}
	return results
}

func pathTraversalHit(body string) bool {
	return strings.Contains(body, "root:x:0:0") ||
		strings.Contains(body, "root:*:") ||
		strings.Contains(body, "/bin/bash") ||
		strings.Contains(body, "/bin/sh") ||
		(strings.Contains(body, "[extensions]") && strings.Contains(body, "win.ini"))
}

func ScanSSTI(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	type sstiTest struct {
		payload  string
		expected string
		engine   string
	}
	tests := []sstiTest{
		{"{{7*7}}", "49", "Jinja2/Twig"},
		{"${7*7}", "49", "FreeMarker/EL/Velocity"},
		{"<%= 7*7 %>", "49", "ERB/EJS"},
		{"#{7*7}", "49", "Ruby Liquid"},
		{"*{7*7}", "49", "Spring EL"},
		{"{{7*'7'}}", "7777777", "Jinja2"},
		{"${{7*7}}", "49", "Pebble/Twirl"},
	}

	p, _ := url.Parse(target.URL)
	params, _ := url.ParseQuery(p.RawQuery)

	for param := range params {
		baseURL, _ := core.SetParam(target.URL, param, "vulntest1234")
		baseline, _, _ := core.DoGET(client, cfg, baseURL)
		echoesValue := strings.Contains(baseline, "vulntest1234")

		for _, t := range tests {
			testURL, err := core.SetParam(target.URL, param, t.payload)
			if err != nil {
				continue
			}
			body, _, err := core.DoGET(client, cfg, testURL)
			if err != nil {
				continue
			}
			if strings.Contains(body, t.expected) && !strings.Contains(baseline, t.expected) && (!echoesValue || !strings.Contains(body, t.payload)) {
				results = append(results, core.ScanResult{
					Type: fmt.Sprintf("Server-Side Template Injection [%s]", t.engine),
					URL:  testURL, Method: "GET", Parameter: param,
					Payload: t.payload, Severity: "HIGH",
					Evidence:  fmt.Sprintf("expression %q evaluated to %q", t.payload, t.expected),
					Timestamp: time.Now(),
				})
				fmt.Printf("  [SSTI] param=%s engine=%s payload=%q\n", param, t.engine, t.payload)
				break
			}
		}
	}

	for _, form := range target.Forms {
		for _, inp := range form.Inputs {
			var formBaseline string
			dBase := core.FormDefaults(form)
			dBase.Set(inp.Name, "vulntest1234")
			if strings.EqualFold(form.Method, "POST") {
				formBaseline, _, _ = core.DoPOST(client, cfg, form.Action, dBase)
			} else {
				if u, err := core.SetFormParams(form.Action, dBase); err == nil {
					formBaseline, _, _ = core.DoGET(client, cfg, u)
				}
			}

			for _, t := range tests {
				d := core.FormDefaults(form)
				d.Set(inp.Name, t.payload)
				var body string
				var err error
				if strings.EqualFold(form.Method, "POST") {
					body, _, err = core.DoPOST(client, cfg, form.Action, d)
				} else {
					u, _ := core.SetFormParams(form.Action, d)
					body, _, err = core.DoGET(client, cfg, u)
				}
				if err != nil {
					continue
				}
				if strings.Contains(body, t.expected) && !strings.Contains(formBaseline, t.expected) && !strings.Contains(body, t.payload) {
					results = append(results, core.ScanResult{
						Type: fmt.Sprintf("SSTI via core.Form [%s]", t.engine),
						URL:  form.Action, Method: form.Method, Parameter: inp.Name,
						Payload: t.payload, Severity: "HIGH",
						Evidence:  fmt.Sprintf("expression %q evaluated to %q", t.payload, t.expected),
						Timestamp: time.Now(),
					})
					fmt.Printf("  [SSTI-FORM] %s input=%s engine=%s\n", form.Action, inp.Name, t.engine)
					break
				}
			}
		}
	}
	return results
}

func scanJSONAPITarget(client *http.Client, cfg *core.Config, apiURL string, sqliLimit, xssLimit int) []core.ScanResult {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil
	}
	core.ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body := core.ReadBody(resp.Body)
	resp.Body.Close()

	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil
	}
	var keys []string
	for k := range doc {
		keys = append(keys, k)
		if len(keys) >= 10 {
			break
		}
	}
	if len(keys) == 0 {
		return nil
	}

	var results []core.ScanResult
	for _, param := range keys {
		bl := core.BaselineResult{}
		if baseBytes, merr := json.Marshal(map[string]string{param: "1"}); merr == nil {
			if breq, rerr := http.NewRequest("POST", apiURL, strings.NewReader(string(baseBytes))); rerr == nil {
				core.ApplyHeaders(breq, cfg)
				breq.Header.Set("Content-Type", "application/json")
				if bresp, derr := client.Do(breq); derr == nil {
					bb := core.ReadBody(bresp.Body)
					bresp.Body.Close()
					bl = core.BaselineResult{Body: bb, BodyLow: strings.ToLower(bb), Length: len(bb), Status: bresp.StatusCode, Valid: true}
				}
			}
		}

	JSONAPISQLiLoop:
		for _, p := range payload.SQLiPayloads[:sqliLimit] {
			bodyBytes, err := json.Marshal(map[string]string{param: p})
			if err != nil {
				continue
			}
			req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(bodyBytes)))
			if err != nil {
				continue
			}
			core.ApplyHeaders(req, cfg)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			b := core.ReadBody(resp.Body)
			resp.Body.Close()
			var ev string
			if bl.Length > 0 && bl.BodyLow != "" {
				ev = DetectSQLiVsBaseline(b, bl)
				if ev == "" && resp.StatusCode == 500 {
					ev = DetectSQLi(b)
				}
			} else if resp.StatusCode == 500 {
				ev = DetectSQLi(b)
			}
			if ev != "" {
				results = append(results, core.ScanResult{
					Type: "SQL Injection via JSON API Body", URL: apiURL,
					Method: "POST/JSON", Parameter: param, Payload: p,
					Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
				})
				fmt.Printf("  [JSON-API-SQLI] %s field=%s\n", apiURL, param)
				break JSONAPISQLiLoop
			}
		}

		for _, p := range payload.XSSPayloads[:xssLimit] {
			bodyBytes, err := json.Marshal(map[string]string{param: p})
			if err != nil {
				continue
			}
			req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(bodyBytes)))
			if err != nil {
				continue
			}
			core.ApplyHeaders(req, cfg)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			b := core.ReadBody(resp.Body)
			resp.Body.Close()
			ct := strings.ToLower(resp.Header.Get("Content-Type"))
			if resp.StatusCode >= 200 && resp.StatusCode <= 299 &&
				strings.Contains(ct, "text/html") && strings.Contains(b, p) {
				results = append(results, core.ScanResult{
					Type: "XSS via JSON API Body", URL: apiURL,
					Method: "POST/JSON", Parameter: param, Payload: p,
					Severity: "MEDIUM", Evidence: "payload reflected unencoded in HTML response",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [JSON-API-XSS] %s field=%s\n", apiURL, param)
				break
			}
		}
	}
	return results
}

func ScanJSONInjection(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	sqliLimit := 10
	if len(payload.SQLiPayloads) < sqliLimit {
		sqliLimit = len(payload.SQLiPayloads)
	}
	xssLimit := 8
	if len(payload.XSSPayloads) < xssLimit {
		xssLimit = len(payload.XSSPayloads)
	}

	if res := scanJSONAPITarget(client, cfg, target.URL, sqliLimit, xssLimit); len(res) > 0 {
		return append(results, res...)
	}

	for _, form := range target.Forms {
		if !strings.EqualFold(form.Method, "POST") || len(form.Inputs) == 0 {
			continue
		}
		for _, inp := range form.Inputs {
			bl := core.BaselineResult{}
			if baseBytes, merr := json.Marshal(map[string]string{inp.Name: "sxel_baseline_1"}); merr == nil {
				if breq, rerr := http.NewRequest("POST", form.Action, strings.NewReader(string(baseBytes))); rerr == nil {
					core.ApplyHeaders(breq, cfg)
					breq.Header.Set("Content-Type", "application/json")
					if bresp, derr := client.Do(breq); derr == nil {
						bb := core.ReadBody(bresp.Body)
						bresp.Body.Close()
						bl = core.BaselineResult{Body: bb, BodyLow: strings.ToLower(bb), Length: len(bb), Status: bresp.StatusCode, Valid: true}
					}
				}
			}

		JSONSQLiLoop:
			for _, p := range payload.SQLiPayloads[:sqliLimit] {
				bodyBytes, err := json.Marshal(map[string]string{inp.Name: p})
				if err != nil {
					continue
				}
				req, err := http.NewRequest("POST", form.Action, strings.NewReader(string(bodyBytes)))
				if err != nil {
					continue
				}
				core.ApplyHeaders(req, cfg)
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				b := core.ReadBody(resp.Body)
				resp.Body.Close()
				var ev string
				if bl.Length > 0 && bl.BodyLow != "" {
					ev = DetectSQLiVsBaseline(b, bl)
					if ev == "" && resp.StatusCode == 500 {
						ev = DetectSQLi(b)
					}
				} else if resp.StatusCode == 500 {
					ev = DetectSQLi(b)
				}
				if ev != "" {
					results = append(results, core.ScanResult{
						Type: "SQL Injection via JSON Body", URL: form.Action,
						Method: "POST/JSON", Parameter: inp.Name, Payload: p,
						Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
					})
					fmt.Printf("  [JSON-SQLI] %s field=%s\n", form.Action, inp.Name)
					break JSONSQLiLoop
				}
			}

		JSONXSSLoop:
			for _, p := range payload.XSSPayloads[:xssLimit] {
				bodyBytes, err := json.Marshal(map[string]string{inp.Name: p})
				if err != nil {
					continue
				}
				req, err := http.NewRequest("POST", form.Action, strings.NewReader(string(bodyBytes)))
				if err != nil {
					continue
				}
				core.ApplyHeaders(req, cfg)
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				b := core.ReadBody(resp.Body)
				resp.Body.Close()
				ct := strings.ToLower(resp.Header.Get("Content-Type"))
				if resp.StatusCode >= 200 && resp.StatusCode <= 299 &&
					strings.Contains(ct, "text/html") && strings.Contains(b, p) {
					results = append(results, core.ScanResult{
						Type: "XSS via JSON Body", URL: form.Action,
						Method: "POST/JSON", Parameter: inp.Name, Payload: p,
						Severity: "MEDIUM", Evidence: "payload reflected unencoded in HTML response",
						Timestamp: time.Now(),
					})
					fmt.Printf("  [JSON-XSS] %s field=%s\n", form.Action, inp.Name)
					break JSONXSSLoop
				}
			}
		}
	}
	return results
}
