package modules

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

// ScanBreach probes for OAuth 2.0 and SAML misconfigurations.
func ScanBreach(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// ── OAuth open redirect checks ──────────────────────────────────────────
	oauthPaths := []string{
		"/oauth/authorize",
		"/oauth2/authorize",
		"/authorize",
		"/auth",
		"/sso/login",
		"/saml/login",
		"/saml2/login",
	}
	redirectParams := []string{"redirect_uri", "redirect", "return_url", "RelayState", "SAMLRequest"}

	for _, path := range oauthPaths {
		for _, param := range redirectParams {
			testURL := target.URL + path + "?" + param + "=https://evil.com"
			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			core.ApplyHeaders(req, cfg)

			noRedir := &http.Client{
				Timeout:   client.Timeout,
				Transport: client.Transport,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := noRedir.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			loc := resp.Header.Get("Location")
			if (resp.StatusCode == 301 || resp.StatusCode == 302) && strings.Contains(loc, "evil.com") {
				results = append(results, core.ScanResult{
					Type:      "OAuth/SAML Open Redirect",
					URL:       testURL,
					Method:    "GET",
					Parameter: param,
					Payload:   "https://evil.com",
					Severity:  "HIGH",
					Evidence:  fmt.Sprintf("Redirect to attacker-controlled URL via %s — Location: %s", param, loc),
					Timestamp: time.Now(),
				})
			}

			// Check if endpoint exists at all
			if resp.StatusCode != 404 {
				if cfg.Verbose {
					fmt.Printf("    \033[90m[breach] found: %s (HTTP %d)\033[0m\n", testURL, resp.StatusCode)
				}
			}
		}
	}

	return results
}
