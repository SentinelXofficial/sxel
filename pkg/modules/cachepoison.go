package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// cachePoisonHeaders are HTTP headers that may be "unkeyed" by caches.
// Injecting values into these headers can poison cached responses for all users.
var cachePoisonHeaders = map[string][]string{
	"X-Forwarded-Host": {
		"evil.com",
		"evil.com%0d%0aX-Cache-Injected:%20true",
	},
	"X-Forwarded-Scheme": {
		"http",
		"https",
	},
	"X-Forwarded-Port": {
		"444",
		"80",
	},
	"X-Original-URL": {
		"/admin",
		"/%2e%2e/admin",
	},
	"X-Rewrite-URL": {
		"/admin",
		"/../admin",
	},
	"X-HTTP-Method-Override": {
		"PUT",
		"DELETE",
	},
	"X-Method-Override": {
		"DELETE",
		"PUT",
	},
	"Forwarded": {
		"for=evil.com;host=evil.com;proto=http",
	},
}

// cachePoisonValues are general-purpose values tested against each header.
var cachePoisonValues = []string{
	"evil.com",
	"evil.com%0d%0aX-Injected:%20sxsc",
	"evil.com%23",
	"//evil.com",
}

// cacheIndicators are response header names that indicate the presence of a cache.
var cacheIndicators = []string{
	"X-Cache", "X-Cache-Hits", "X-Cache-Lookup",
	"X-Drupal-Cache", "X-Varnish", "X-Varnish-Cache",
	"CF-Cache-Status", "X-Akamai-Cache", "Age",
	"X-Proxy-Cache", "X-Served-By", "X-Timer",
	"X-Backend", "Via", "X-CDN",
}

// ScanCachePoison tests for web cache poisoning by injecting values into
// commonly unkeyed HTTP headers and checking for reflection or cache hits.
func ScanCachePoison(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// ── 1. Detect if a cache is in front ───────────────────────────────────
	req, err := http.NewRequest("GET", target.URL, nil)
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

	hasCache := false
	for _, hdr := range cacheIndicators {
		if resp.Header.Get(hdr) != "" {
			hasCache = true
			if cfg.Verbose {
				output.Verbose("[cache-poison] cache detected: %s=%s", hdr, resp.Header.Get(hdr))
			}
			break
		}
	}

	// ── 2. First pass: send poisoned requests and note any reflection ─────

	// Use a client that doesn't follow redirects so we can inspect Location
	noRedir := &http.Client{
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test known unkeyed headers with specific values
	for hdrName, values := range cachePoisonHeaders {
		for _, val := range values {
			r, err := http.NewRequest("GET", target.URL, nil)
			if err != nil {
				continue
			}
			core.ApplyHeaders(r, cfg)
			r.Header.Set(hdrName, val)
			resp2, err := noRedir.Do(r)
			if err != nil {
				continue
			}
			bodyBytes, _ := io.ReadAll(resp2.Body)
			resp2.Body.Close()
			body := string(bodyBytes)

			// Check for reflection in response body, Location header, or Set-Cookie
			reflected := false
			evidence := ""

			if strings.Contains(body, val) {
				reflected = true
				evidence = fmt.Sprintf("payload %q reflected in response body (HTTP %d)", val, resp2.StatusCode)
			} else if loc := resp2.Header.Get("Location"); strings.Contains(loc, val) {
				reflected = true
				evidence = fmt.Sprintf("payload %q reflected in Location header: %s", val, loc)
			} else if loc := resp2.Header.Get("Location"); strings.Contains(loc, "evil.com") {
				reflected = true
				evidence = fmt.Sprintf("open redirect via %s — Location: %s", hdrName, loc)
			}

			if reflected {
				sev := "HIGH"
				if !hasCache {
					sev = "MEDIUM"
				}
				results = append(results, core.ScanResult{
					Type:      "Web Cache Poisoning",
					URL:       target.URL,
					Method:    "GET",
					Parameter: hdrName,
					Payload:   val,
					Severity:  sev,
					Evidence:  evidence,
					Timestamp: time.Now(),
				})
				break // one finding per header is enough
			}
		}
	}

	// ── 3. Second pass: test general poison values against additional headers ──
	extraHeaders := []string{"X-Forwarded-For", "X-Real-IP", "True-Client-IP", "X-Client-IP"}
	for _, hdrName := range extraHeaders {
		for _, val := range cachePoisonValues {
			r, err := http.NewRequest("GET", target.URL, nil)
			if err != nil {
				continue
			}
			core.ApplyHeaders(r, cfg)
			r.Header.Set(hdrName, val)
			resp2, err := noRedir.Do(r)
			if err != nil {
				continue
			}
			bodyBytes, _ := io.ReadAll(resp2.Body)
			resp2.Body.Close()
			body := string(bodyBytes)

			if strings.Contains(body, val) || strings.Contains(resp2.Header.Get("Location"), val) {
				results = append(results, core.ScanResult{
					Type:      "Web Cache Poisoning (IP Header Reflection)",
					URL:       target.URL,
					Method:    "GET",
					Parameter: hdrName,
					Payload:   val,
					Severity:  "MEDIUM",
					Evidence:  fmt.Sprintf("payload %q reflected via %s header", val, hdrName),
					Timestamp: time.Now(),
				})
				break
			}
		}
	}

	// ── 4. Host header poisoning (separate from existing Host header scan) ──
	for _, val := range []string{"evil.com"} {
		r, err := http.NewRequest("GET", target.URL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(r, cfg)
		r.Host = val
		resp2, err := noRedir.Do(r)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		body := string(bodyBytes)

		// Check if absolute URLs in the response body point to our injected host
		scheme := "https://"
		if p, err := url.Parse(target.URL); err == nil && p.Scheme == "http" {
			scheme = "http://"
		}
		if strings.Contains(body, scheme+val) || strings.Contains(body, "//"+val) {
			results = append(results, core.ScanResult{
				Type:      "Web Cache Poisoning (Host Header)",
				URL:       target.URL,
				Method:    "GET",
				Parameter: "Host",
				Payload:   val,
				Severity:  "HIGH",
				Evidence:  fmt.Sprintf("Host %q reflected in absolute URLs in response body — cache poisoning possible", val),
				Timestamp: time.Now(),
			})
		}
	}

	return results
}
