package modules

import (
	"net/http"
	"net/url"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/payload"
)

func ScanSQLi(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}
	for param := range params {
		if cfg.Verbose {
			output.Verbose("[sqli-get] param=%s", param)
		}
		baseline := FetchBaseline(client, cfg, target.URL, param)
	SQLiParamLoop:
		for _, base := range payload.SQLiPayloads {
			variants := []string{base}
			if cfg.WAFBypass {
				variants = WAFBypassSQL(base)
			}
			for _, payload := range variants {
				testURL, err := core.SetParamRaw(target.URL, param, payload)
				if err != nil {
					continue
				}
				body, _, err := core.DoGET(client, cfg, testURL)
				if err != nil {
					continue
				}
				if ev := DetectSQLiVsBaseline(body, baseline); ev != "" {
					results = append(results, core.ScanResult{
						Type: "SQL Injection (Error-Based)" + dbmsLabel(body), URL: testURL,
						Method: "GET", Parameter: param, Payload: payload,
						Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
					})
					break SQLiParamLoop
				}
			}
		}
	}

	for _, form := range target.Forms {
		bl := FetchFormBaseline(client, cfg, form)
		if !bl.Valid {
			continue
		}
		for _, inp := range form.Inputs {
			if cfg.Verbose {
				output.Verbose("[sqli-form] %s %s input=%s", form.Method, form.Action, inp.Name)
			}
		SQLiFormLoop:
			for _, base := range payload.SQLiPayloads {
				variants := []string{base}
				if cfg.WAFBypass {
					variants = WAFBypassSQL(base)
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
					if ev := DetectSQLiVsBaseline(body, bl); ev != "" {
						results = append(results, core.ScanResult{
							Type: "SQL Injection via Form" + dbmsLabel(body), URL: form.Action,
							Method: form.Method, Parameter: inp.Name, Payload: pld,
							Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
						})
						break SQLiFormLoop
					}
				}
			}
		}
	}
	results = append(results, ScanUnionSQLi(client, cfg, target)...)
	results = append(results, ScanSecondOrderSQLi(client, cfg, target)...)
	return results
}
