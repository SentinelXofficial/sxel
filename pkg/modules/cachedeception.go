package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

var cacheDeceptionSuffixes = []string{
	"%2f..%2f..%2f",
	"%2f..%2f",
	";%2f..%2f",
	"%3f",
	"%23",
	"/",
	"/..%2f",
	"%2e%2e%2f",
}

var cacheDeceptionExts = []string{".css", ".js", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico", ".txt", ".json"}

func ScanCacheDeception(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	baseStatus, baseBody, baseLen, ok := probeCacheBase(client, cfg, target.URL)
	if !ok {
		return results
	}

	noRedir := &http.Client{
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ext := cacheDeceptionExts[0]
	if p, err := url.Parse(target.URL); err == nil {
		path := strings.ToLower(p.Path)
		for _, e := range cacheDeceptionExts {
			if strings.HasSuffix(path, e) {
				ext = e
				break
			}
		}
	}

	marker := randomHex(8)
	basePathOnly := target.URL
	if p, err := url.Parse(target.URL); err == nil {
		q := p.RawQuery
		if q != "" {
			p.RawQuery = ""
			basePathOnly = p.String()
		}
	}
	for _, suffix := range cacheDeceptionSuffixes {
		deceitURL := strings.TrimRight(basePathOnly, "/") + "/" + marker + suffix + ext
		r, err := http.NewRequest("GET", deceitURL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(r, cfg)
		resp, err := noRedir.Do(r)
		if err != nil {
			continue
		}
		body := core.ReadBody(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != baseStatus {
			continue
		}
		normDiff := normalizeRaceBody(body) == normalizeRaceBody(baseBody)
		lenClose := absInt(len(body)-baseLen) <= int(float64(baseLen)*0.15+64)
		if !normDiff && !lenClose {
			continue
		}

		hasCache := false
		for _, hdr := range cacheIndicators {
			if resp.Header.Get(hdr) != "" {
				hasCache = true
				break
			}
		}

		sev := "MEDIUM"
		if hasCache {
			sev = "HIGH"
		}
		results = append(results, core.ScanResult{
			Type:      "Web Cache Deception",
			URL:       deceitURL,
			Method:    "GET",
			Parameter: "path",
			Payload:   suffix + ext,
			Severity:  sev,
			Evidence: fmt.Sprintf("appending %q to the path returns the same content as %s (HTTP %d) — a cache layer may store the private response under a static-looking URL",
				suffix+ext, target.URL, baseStatus),
			Timestamp: time.Now(),
			Extra: map[string]string{
				"original_url":  target.URL,
				"base_status":   fmt.Sprintf("%d", baseStatus),
				"base_length":   fmt.Sprintf("%d", baseLen),
				"deceit_length": fmt.Sprintf("%d", len(body)),
				"cache_headers": fmt.Sprintf("%v", hasCache),
			},
		})
		if cfg.Verbose {
			output.Verbose("[cache-deception] %s -> %d (%d bytes, cache=%v)", deceitURL, resp.StatusCode, len(body), hasCache)
		}
		break
	}

	return results
}

func probeCacheBase(client *http.Client, cfg *core.Config, targetURL string) (int, string, int, bool) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return 0, "", 0, false
	}
	core.ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", 0, false
	}
	body := core.ReadBody(resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return resp.StatusCode, body, len(body), false
	}
	return resp.StatusCode, body, len(body), true
}
