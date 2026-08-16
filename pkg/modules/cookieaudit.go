package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"strings"
	"time"
)

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
	core.ReadBody(resp.Body)
	resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return results
	}

	for _, ck := range cookies {
		low := strings.ToLower(ck.Name)

		if low == "sxel" {
			continue
		}

		if !ck.Secure && strings.HasPrefix(strings.ToLower(targetURL), "https://") {
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
		}

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
		}

		sameSite := sameSiteToString(ck.SameSite)
		switch sameSite {
		case "unset":
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
		case "none":
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
			}
		}

		domain := ck.Domain
		if domain != "" {
			if broadDomainScope(extractHost(targetURL), domain) {
				results = append(results, core.ScanResult{
					Type:      "Cookie Security — Broad Domain Scope",
					URL:       targetURL,
					Method:    "GET",
					Parameter: ck.Name,
					Payload:   fmt.Sprintf("Domain=%s", domain),
					Severity:  "LOW",
					Evidence:  fmt.Sprintf("Cookie %q Domain=%q is broader than the page host %q — accessible to sibling subdomains", ck.Name, domain, extractHost(targetURL)),
					Timestamp: time.Now(),
				})
				if cfg.Verbose {
					output.Verbose("[COOKIE-AUDIT] %s: broad domain %q (page host %q)", ck.Name, domain, extractHost(targetURL))
				}
			}
		}

		longExpiry := false
		expiryDays := 0
		if ck.MaxAge > 86400*30 && ck.MaxAge > 0 {
			longExpiry = true
			expiryDays = ck.MaxAge / 86400
		} else if !ck.Expires.IsZero() {
			days := int(time.Until(ck.Expires).Hours() / 24)
			if days > 30 {
				longExpiry = true
				expiryDays = days
			}
		}
		if longExpiry {
			results = append(results, core.ScanResult{
				Type:      "Cookie Security — Long Expiry",
				URL:       targetURL,
				Method:    "GET",
				Parameter: ck.Name,
				Payload:   fmt.Sprintf("expires in %d days", expiryDays),
				Severity:  "LOW",
				Evidence:  fmt.Sprintf("Cookie %q expires in %d days — consider a shorter lifetime", ck.Name, expiryDays),
				Timestamp: time.Now(),
			})
		}

		if ck.Path == "/" || ck.Path == "" {
			if cfg.Verbose {
				output.Verbose("[COOKIE-AUDIT] %s: path=%q (all paths)", ck.Name, ck.Path)
			}
		}
	}

	return results
}

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

func broadDomainScope(pageHost, cookieDomain string) bool {
	siteHost := strings.ToLower(pageHost)
	cookieDom := strings.TrimPrefix(strings.ToLower(cookieDomain), ".")
	return cookieDom != siteHost &&
		!strings.HasSuffix(cookieDom, "."+siteHost) &&
		strings.HasSuffix(siteHost, "."+cookieDom)
}
