package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var csrfTokenNames = []string{
	"csrf", "csrf_token", "csrftoken", "_csrf", "_csrf_token",
	"xsrf", "xsrf_token", "_token", "authenticity_token",
	"_wpnonce", "nonce", "token", "__RequestVerificationToken",
}

func isCSRFTokenName(name string) bool {
	low := strings.ToLower(name)
	for _, kw := range csrfTokenNames {
		if low == kw || strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func ScanCSRF(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	for _, form := range target.Forms {
		method := strings.ToUpper(form.Method)
		if method != "POST" && method != "PUT" && method != "DELETE" && method != "PATCH" {
			continue
		}

		hasCSRF := form.TokenName != ""
		var csrfField string
		if hasCSRF {
			csrfField = form.TokenName
		} else {
			for _, inp := range form.Inputs {
				if isCSRFTokenName(inp.Name) {
					hasCSRF = true
					csrfField = inp.Name
					break
				}
			}
		}

		action := form.Action
		if action == "" {
			action = target.URL
		}

		if !hasCSRF {
			sev := "LOW"
			evidence := fmt.Sprintf("core.Form at %s uses %s without any CSRF token field — verify with manual review", action, method)
			if cfg.Cookie != "" && !testCSRFEnforcement(client, form, action, "", target.URL, cfg) {
				sev = "HIGH"
				evidence = fmt.Sprintf("core.Form at %s uses %s without any CSRF token field — plain submission was accepted by the server (enforcement bypass confirmed)", action, method)
			}
			results = append(results, core.ScanResult{
				Type:      "CSRF — Missing Anti-CSRF Token",
				URL:       action,
				Method:    method,
				Parameter: "form",
				Payload:   "no csrf token found",
				Severity:  sev,
				Evidence:  evidence,
				Timestamp: time.Now(),
			})
			continue
		}

		if cfg.Cookie == "" {
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

		enforced := testCSRFEnforcement(client, form, action, csrfField, target.URL, cfg)
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
		}
	}

	return results
}

func testCSRFEnforcement(client *http.Client, form core.Form, action, csrfField, pageURL string, cfg *core.Config) bool {
	method := strings.ToUpper(form.Method)
	if method != "POST" && method != "PUT" && method != "DELETE" && method != "PATCH" {
		return false
	}

	if client == nil {
		client = core.NewHTTPClient(cfg)
	}

	submit := func(csrfMode int) (body string, status int, loc string, ok bool) {
		data := url.Values{}
		for _, inp := range form.Inputs {
			val := inp.Value
			if val == "" {
				val = "test"
			}
			if inp.Name == csrfField {
				switch csrfMode {
				case 0:
					continue
				case 2:
					val = "invalid-" + val + "-bypass"
				}
			}
			data.Set(inp.Name, val)
		}
		if form.TokenName != "" {
			switch csrfMode {
			case 1:
				data.Set(form.TokenName, form.TokenValue)
			case 2:
				data.Set(form.TokenName, "invalid-"+form.TokenValue+"-bypass")
			}
		}
		req, err := http.NewRequest(method, action, strings.NewReader(data.Encode()))
		if err != nil {
			return "", 0, "", false
		}
		core.ApplyHeaders(req, cfg)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			return "", 0, "", false
		}
		defer resp.Body.Close()
		return core.ReadBody(resp.Body), resp.StatusCode, resp.Header.Get("Location"), true
	}

	_, baseStatus, baseLoc, ok := submit(1)
	if !ok {
		return true
	}
	noTokBody, noTokStatus, noTokLoc, ok := submit(0)
	if !ok {
		return true
	}
	invTokBody, invTokStatus, invTokLoc, ok := submit(2)
	if !ok {
		return true
	}

	rejection := func(body string, status int) bool {
		if status == 403 {
			return true
		}
		if status >= 400 && status < 500 {
			low := strings.ToLower(body)
			for _, kw := range []string{"error", "invalid", "rejected", "missing", "required", "forbidden", "csrf", "token"} {
				if strings.Contains(low, kw) {
					return true
				}
			}
		}
		return false
	}

	successSignal := func(body string, status int) bool {
		if status < 200 || status >= 400 {
			return false
		}
		low := strings.ToLower(body)
		for _, kw := range []string{"success", "saved", "updated", "logged", "welcome", "dashboard"} {
			if strings.Contains(low, kw) {
				return true
			}
		}
		return false
	}

	notEnforced := false
	if baseStatus >= 200 && baseStatus < 400 {
		if noTokStatus >= 200 && noTokStatus < 400 && !rejection(noTokBody, noTokStatus) {
			if successSignal(noTokBody, noTokStatus) || (baseLoc != "" && noTokLoc == baseLoc) {
				notEnforced = true
			}
		}
		if invTokStatus >= 200 && invTokStatus < 400 && !rejection(invTokBody, invTokStatus) {
			if successSignal(invTokBody, invTokStatus) || (baseLoc != "" && invTokLoc == baseLoc) {
				notEnforced = true
			}
		}
	}
	return !notEnforced
}
