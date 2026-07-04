package modules

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/payload"
)

// ScanXSS tests a target for reflected XSS via URL params and forms.
func ScanXSS(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// ── URL parameters ───────────────────────────────────────────────────
	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}
	for param := range params {
		if cfg.Verbose {
			output.Verbose("[xss-get] param=%s", param)
		}
	XSSParamLoop:
		for _, base := range payload.XSSPayloads {
			variants := []string{base}
			if cfg.WAFBypass {
				variants = WAFBypassXSS(base)
			}
			for _, pld := range variants {
				testURL, err := core.SetParam(target.URL, param, pld)
				if err != nil {
					continue
				}
				body, _, err := core.DoGET(client, cfg, testURL)
				if err != nil {
					continue
				}
				if strings.Contains(body, pld) {
					results = append(results, core.ScanResult{
						Type: "XSS (Reflected)", URL: testURL,
						Method: "GET", Parameter: param, Payload: pld,
						Severity: "MEDIUM", Evidence: "payload reflected unencoded",
						Timestamp: time.Now(),
					})
					break XSSParamLoop
				}
			}
		}
	}

	// ── Forms ────────────────────────────────────────────────────────────
	for _, form := range target.Forms {
		for _, inp := range form.Inputs {
		XSSFormLoop:
			for _, base := range payload.XSSPayloads {
				variants := []string{base}
				if cfg.WAFBypass {
					variants = WAFBypassXSS(base)
				}
				for _, pld := range variants {
					var body string
								var err error
					if form.Method == "POST" {
						d := core.FormDefaults(form)
						d.Set(inp.Name, pld)
						body, _, err = core.DoPOST(client, cfg, form.Action, d)
					} else {
						d := core.FormDefaults(form)
						d.Set(inp.Name, pld)
						testURL, _ := core.SetFormParams(form.Action, d)
						body, _, err = core.DoGET(client, cfg, testURL)
					}
					if err != nil {
						continue
					}
					if strings.Contains(body, pld) {
						results = append(results, core.ScanResult{
							Type: "XSS (Reflected) via Form", URL: form.Action,
							Method: form.Method, Parameter: inp.Name, Payload: pld,
							Severity: "MEDIUM", Evidence: "payload reflected unencoded",
							Timestamp: time.Now(),
						})
						break XSSFormLoop
					}
				}
			}
		}
	}
	return results
}
