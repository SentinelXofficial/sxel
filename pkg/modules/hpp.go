package modules

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func hppMarker() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "hppx" + hex.EncodeToString(b)
}

func ScanHPP(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	marker := hppMarker()

	params := map[string][]string{}
	if p, err := url.Parse(target.URL); err == nil {
		q, _ := url.ParseQuery(p.RawQuery)
		for k := range q {
			params[k] = q[k]
		}
	}
	probeURL := target.URL
	for k, vals := range params {
		base, err := url.Parse(target.URL)
		if err != nil {
			continue
		}
		raw := base.RawQuery
		if raw != "" {
			raw += "&"
		}
		orig := "1"
		if len(vals) > 0 && vals[0] != "" {
			orig = vals[0]
		}
		raw += url.QueryEscape(k) + "=" + url.QueryEscape(orig) + "&" + url.QueryEscape(k) + "=" + marker
		base.RawQuery = raw
		probeURL = base.String()

		body, status, err := core.DoGET(client, cfg, probeURL)
		if err != nil || status >= 400 {
			continue
		}
		low := strings.ToLower(body)
		lowMarker := strings.ToLower(marker)
		if strings.Contains(low, lowMarker) {
			sev := "MEDIUM"
			ev := fmt.Sprintf("injected duplicate value %q was processed by the server", marker)
			idx := strings.Index(low, lowMarker)
			start := idx - 40
			if start < 0 {
				start = 0
			}
			end := idx + len(lowMarker) + 40
			if end > len(low) {
				end = len(low)
			}
			window := low[start:end]
			lowOrig := strings.ToLower(orig)
			if lowOrig != "" && strings.Contains(window, lowOrig) {
				sev = "HIGH"
				ev = fmt.Sprintf("both values processed together: original %q and injected %q appear in the same response region", orig, marker)
			}
			results = append(results, core.ScanResult{
				Type: "HTTP Parameter Pollution", URL: probeURL, Method: "GET",
				Parameter: k, Payload: k + "=" + orig + "&" + k + "=" + marker,
				Severity: sev, Evidence: ev, Timestamp: time.Now(),
			})
			fmt.Printf("  [HPP] %s param=%s (%s)\n", probeURL, k, sev)
		}
	}

	for _, form := range target.Forms {
		if !strings.EqualFold(form.Method, "POST") || len(form.Inputs) == 0 {
			continue
		}
		for _, inp := range form.Inputs {
			d := core.FormDefaults(form)
			d.Set(inp.Name, "1")
			body, status, err := core.DoPOST(client, cfg, form.Action, d)
			if err != nil || status >= 400 {
				continue
			}
			_ = body
			d.Set(inp.Name, "1")
			d.Add(inp.Name, marker)
			body2, status, err := core.DoPOST(client, cfg, form.Action, d)
			if err != nil || status >= 400 {
				continue
			}
			if strings.Contains(strings.ToLower(body2), strings.ToLower(marker)) && !strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
				results = append(results, core.ScanResult{
					Type: "HTTP Parameter Pollution", URL: form.Action, Method: "POST",
					Parameter: inp.Name, Payload: inp.Name + "=1&" + inp.Name + "=" + marker,
					Severity: "MEDIUM", Evidence: "duplicated POST parameter was processed by the server",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [HPP] %s param=%s (POST)\n", form.Action, inp.Name)
				break
			}
		}
	}
	return results
}
