package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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
			fmt.Printf("    \033[90m[xss-get] param=%s\033[0m\n", param)
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
				body, status, err := core.DoGET(client, cfg, testURL)
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
					fmt.Printf("  \033[33m[✗ XSS]\033[0m GET param=%s payload=%q HTTP=%d\n", param, pld, status)
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
					var status int
					var err error
					if form.Method == "POST" {
						d := core.FormDefaults(form)
						d.Set(inp.Name, pld)
						body, status, err = core.DoPOST(client, cfg, form.Action, d)
					} else {
						testURL, _ := core.SetParam(form.Action, inp.Name, pld)
						body, status, err = core.DoGET(client, cfg, testURL)
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
						fmt.Printf("  \033[33m[✗ XSS-FORM]\033[0m %s %s input=%s HTTP=%d\n",
							form.Method, form.Action, inp.Name, status)
						break XSSFormLoop
					}
				}
			}
		}
	}
	return results
}
