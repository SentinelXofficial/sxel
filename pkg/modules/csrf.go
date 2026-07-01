package modules

import (
	"github.com/SentinelXofficial/sxel/pkg/core"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// csrfTokenNames are common CSRF token parameter names searched in forms.
var csrfTokenNames = []string{
	"csrf", "csrf_token", "csrftoken", "_csrf", "_csrf_token",
	"xsrf", "xsrf_token", "_token", "authenticity_token",
	"_wpnonce", "nonce", "token", "__RequestVerificationToken",
}

// isCSRFTokenName returns true if the input name looks like a CSRF token.
func isCSRFTokenName(name string) bool {
	low := strings.ToLower(name)
	for _, kw := range csrfTokenNames {
		if low == kw || strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// ScanCSRF checks each form for CSRF token presence and optionally replays
// a request without the token to see if the server enforces it.
func ScanCSRF(cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	for _, form := range target.Forms {
		// Only test state-changing methods
		method := strings.ToUpper(form.Method)
		if method != "POST" && method != "PUT" && method != "DELETE" && method != "PATCH" {
			continue
		}

		hasCSRF := false
		var csrfField string
		for _, inp := range form.Inputs {
			if isCSRFTokenName(inp.Name) {
				hasCSRF = true
				csrfField = inp.Name
				break
			}
		}

		action := form.Action
		if action == "" {
			action = target.URL
		}

		if !hasCSRF {
			// No CSRF token found at all — flag as vulnerability
			results = append(results, core.ScanResult{
				Type:      "CSRF — Missing Anti-CSRF Token",
				URL:       action,
				Method:    method,
				Parameter: "form",
				Payload:   "no csrf token found",
				Severity:  "HIGH",
				Evidence:  fmt.Sprintf("core.Form at %s uses %s without any CSRF token field", action, method),
				Timestamp: time.Now(),
			})
			if cfg.Verbose {
				fmt.Printf("  \033[31m[✗ CSRF]\033[0m %s %s — no token field in form\n", method, action)
			}
			continue
		}

		// CSRF token found — test if it's actually enforced by replaying without it
		if cfg.Cookie == "" {
			// Without a session cookie we can't meaningfully test enforcement,
			// but we note the token exists (informational).
			results = append(results, core.ScanResult{
				Type:      "CSRF — Token Present (Enforcement Unknown)",
				URL:       action,
				Method:    method,
				Parameter: csrfField,
				Payload:   "token field exists",
				Severity:  "INFO",
				Evidence:  fmt.Sprintf("CSRF token field %q found — supply --cookie to test enforcement", csrfField),
				Timestamp: time.Now(),
			})
			continue
		}

		// Replay without token to test enforcement
		enforced := testCSRFEnforcement(form, action, csrfField, target.URL, cfg)
		if !enforced {
			results = append(results, core.ScanResult{
				Type:      "CSRF — Token Not Enforced",
				URL:       action,
				Method:    method,
				Parameter: csrfField,
				Payload:   "request succeeded without csrf token",
				Severity:  "HIGH",
				Evidence:  fmt.Sprintf("Token %q exists but server accepted request without it", csrfField),
				Timestamp: time.Now(),
			})
			if cfg.Verbose {
				fmt.Printf("  \033[31m[✗ CSRF]\033[0m %s %s — token %q not enforced\n", method, action, csrfField)
			}
		}
	}

	return results
}

// testCSRFEnforcement replays a form submission without the CSRF token field.
// Returns true if the server rejected the request (token IS enforced).
func testCSRFEnforcement(form core.Form, action, csrfField, pageURL string, cfg *core.Config) bool {
	// Build request without the CSRF token
	if strings.ToUpper(form.Method) == "POST" {
		data := url.Values{}
		for _, inp := range form.Inputs {
			if inp.Name == csrfField {
				continue // skip the token
			}
			val := inp.Value
			if val == "" {
				val = "test"
			}
			data.Set(inp.Name, val)
		}
		// Use a client that follows redirects to see the final outcome
		client := &http.Client{Timeout: time.Duration(cfg.Timeout) * time.Second}
		req, err := http.NewRequest("POST", action, strings.NewReader(data.Encode()))
		if err != nil {
			return true // assume enforced
		}
		core.ApplyHeaders(req, cfg)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			return true
		}
		resp.Body.Close()
		// 200 or 3xx = likely accepted without token → NOT enforced
		return !(resp.StatusCode >= 200 && resp.StatusCode < 400)
	}
	return true // can't test non-POST forms for enforcement
}
