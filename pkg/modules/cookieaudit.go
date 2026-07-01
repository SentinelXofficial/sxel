package modules

import (
	"github.com/SentinelXofficial/sxel/pkg/core"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AuditCookies inspects Set-Cookie headers for missing security flags and
// overly broad Domain/Path settings.
func AuditCookies(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
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

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return results
	}

	for _, ck := range cookies {
		low := strings.ToLower(ck.Name)

		// Skip session cookies set by the scanner itself
		if low == "sxsc" {
			continue
		}

		// ── Missing Secure flag ──────────────────────────────────────────
		if !ck.Secure && strings.HasPrefix(targetURL, "https://") {
			results = append(results, core.ScanResult{
				Type:      "Cookie Security — Missing Secure Flag",
				URL:       targetURL,
				Method:    "GET",
				Parameter: ck.Name,
				Payload:   "Secure=false",
				Severity:  "MEDIUM",
				Evidence:  fmt.Sprintf("Cookie %q set over HTTPS without Secure flag — may be sent over unencrypted connections", ck.Name),
				Timestamp: time.Now(),
			})
			fmt.Printf("  \033[33m[✗ COOKIE-AUDIT]\033[0m %s: missing Secure flag\n", ck.Name)
		}

		// ── Missing HttpOnly ─────────────────────────────────────────────
		if !ck.HttpOnly {
			results = append(results, core.ScanResult{
				Type:      "Cookie Security — Missing HttpOnly Flag",
				URL:       targetURL,
				Method:    "GET",
				Parameter: ck.Name,
				Payload:   "HttpOnly=false",
				Severity:  "MEDIUM",
				Evidence:  fmt.Sprintf("Cookie %q lacks HttpOnly — readable by JavaScript (XSS risk)", ck.Name),
				Timestamp: time.Now(),
			})
			fmt.Printf("  \033[33m[✗ COOKIE-AUDIT]\033[0m %s: missing HttpOnly flag\n", ck.Name)
		}

		// ── Missing or weak SameSite ─────────────────────────────────────
		sameSite := sameSiteToString(ck.SameSite)
		switch sameSite {
		case "unset": // Go http library: SameSiteDefaultMode = 0 = unset
			results = append(results, core.ScanResult{
				Type:      "Cookie Security — SameSite Not Set",
				URL:       targetURL,
				Method:    "GET",
				Parameter: ck.Name,
				Payload:   "SameSite=unset",
				Severity:  "MEDIUM",
				Evidence:  fmt.Sprintf("Cookie %q has no SameSite attribute — susceptible to CSRF", ck.Name),
				Timestamp: time.Now(),
			})
			fmt.Printf("  \033[33m[✗ COOKIE-AUDIT]\033[0m %s: SameSite not set\n", ck.Name)
		case "none":
			// SameSite=None without Secure is dangerous
			if !ck.Secure {
				results = append(results, core.ScanResult{
					Type:      "Cookie Security — SameSite=None Without Secure",
					URL:       targetURL,
					Method:    "GET",
					Parameter: ck.Name,
					Payload:   "SameSite=None;Secure=false",
					Severity:  "HIGH",
					Evidence:  fmt.Sprintf("Cookie %q uses SameSite=None without Secure — browsers will reject this cookie in modern versions", ck.Name),
					Timestamp: time.Now(),
				})
				fmt.Printf("  \033[31m[✗ COOKIE-AUDIT]\033[0m %s: SameSite=None without Secure\n", ck.Name)
			}
		}

		// ── Overly broad Domain ──────────────────────────────────────────
		domain := ck.Domain
		if domain != "" {
			// Cookies with leading dot or top-level-ish domains
			if strings.HasPrefix(domain, ".") || strings.Count(domain, ".") < 2 {
				sev := "LOW"
				if !strings.Contains(domain, ".") {
					sev = "MEDIUM" // "localhost" or similar
				}
				results = append(results, core.ScanResult{
					Type:      "Cookie Security — Broad Domain Scope",
					URL:       targetURL,
					Method:    "GET",
					Parameter: ck.Name,
					Payload:   fmt.Sprintf("Domain=%s", domain),
					Severity:  sev,
					Evidence:  fmt.Sprintf("Cookie %q Domain=%q may be accessible to subdomains or sibling domains", ck.Name, domain),
					Timestamp: time.Now(),
				})
				if cfg.Verbose {
					fmt.Printf("  \033[90m[COOKIE-AUDIT]\033[0m %s: broad domain %q\n", ck.Name, domain)
				}
			}
		}

		// ── Long expiry — session cookies should be short-lived ──────────
		if ck.MaxAge > 86400*30 && ck.MaxAge > 0 {
			results = append(results, core.ScanResult{
				Type:      "Cookie Security — Long Expiry",
				URL:       targetURL,
				Method:    "GET",
				Parameter: ck.Name,
				Payload:   fmt.Sprintf("MaxAge=%ds", ck.MaxAge),
				Severity:  "LOW",
				Evidence:  fmt.Sprintf("Cookie %q expires in %d days — consider a shorter lifetime", ck.Name, ck.MaxAge/86400),
				Timestamp: time.Now(),
			})
		}

		// ── Cookie path too broad ────────────────────────────────────────
		if ck.Path == "/" || ck.Path == "" {
			// This is common and not always a vulnerability, but worth noting
			if cfg.Verbose {
				fmt.Printf("  \033[90m[COOKIE-AUDIT]\033[0m %s: path=%q (all paths)\n", ck.Name, ck.Path)
			}
		}
	}

	return results
}

// sameSiteToString converts http.SameSite (an int) to a human-readable string.
func sameSiteToString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteNoneMode:
		return "none"
	default:
		return "unset"
	}
}
