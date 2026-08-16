package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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

var cachePoisonValues = []string{
	"evil.com",
	"evil.com%0d%0aX-Injected:%20sxel",
	"evil.com%23",
	"//evil.com",
}

var cacheIndicators = []string{
	"X-Cache", "X-Cache-Hits", "X-Cache-Lookup",
	"X-Drupal-Cache", "X-Varnish", "X-Varnish-Cache",
	"CF-Cache-Status", "X-Akamai-Cache", "Age",
	"X-Proxy-Cache", "X-Served-By", "X-Timer",
	"X-Backend", "Via", "X-CDN",
}

func ScanCachePoison(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	req, err := http.NewRequest("GET", target.URL, nil)
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

	noRedir := &http.Client{
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseStatus := 0
	baseBody := ""
	baseLoc := ""
	if bReq, err := http.NewRequest("GET", target.URL, nil); err == nil {
		core.ApplyHeaders(bReq, cfg)
		if bResp, berr := noRedir.Do(bReq); berr == nil {
			baseStatus = bResp.StatusCode
			baseBody = core.ReadBody(bResp.Body)
			baseLoc = bResp.Header.Get("Location")
			bResp.Body.Close()
		}
	}
	if baseStatus == 0 {
		output.Warn("Cache poisoning: baseline request failed for %s — results may be unreliable", target.URL)
		return nil
	}

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
			bodyBytes := core.ReadBody(resp2.Body)
			resp2.Body.Close()
			body := bodyBytes

			reflected := false
			evidence := ""
			differs := resp2.StatusCode != baseStatus || absInt(len(body)-len(baseBody)) > 256

			decoded := val
			if d, derr := url.QueryUnescape(val); derr == nil && d != val {
				decoded = d
			}

			if (strings.Contains(body, val) || strings.Contains(body, decoded)) && !strings.Contains(baseBody, val) && differs {
				reflected = true
				evidence = fmt.Sprintf("payload %q reflected in response body (HTTP %d), absent from baseline — unkeyed header poisoning possible", val, resp2.StatusCode)
			} else if loc := resp2.Header.Get("Location"); (strings.Contains(loc, val) || strings.Contains(loc, decoded)) && !strings.Contains(baseLoc, val) && resp2.StatusCode != baseStatus {
				reflected = true
				evidence = fmt.Sprintf("payload %q reflected in Location header: %s", val, loc)
			} else if loc := resp2.Header.Get("Location"); strings.Contains(loc, "evil.com") && !strings.Contains(baseLoc, "evil.com") && resp2.StatusCode != baseStatus {
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
				break
			}
		}
	}

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
			bodyBytes := core.ReadBody(resp2.Body)
			resp2.Body.Close()
			body := bodyBytes

			if strings.Contains(body, val) && !strings.Contains(baseBody, val) ||
				strings.Contains(resp2.Header.Get("Location"), val) && !strings.Contains(baseLoc, val) {
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

	for _, val := range []string{"evil.com", "example.com", "cachepoison" + randomHex(6) + ".test"} {
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
		bodyBytes := core.ReadBody(resp2.Body)
		resp2.Body.Close()
		body := bodyBytes

		scheme := "https://"
		if p, err := url.Parse(target.URL); err == nil && p.Scheme == "http" {
			scheme = "http://"
		}
		if strings.Contains(body, scheme+val) && !strings.Contains(baseBody, scheme+val) ||
			strings.Contains(body, "//"+val) && !strings.Contains(baseBody, "//"+val) {
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
