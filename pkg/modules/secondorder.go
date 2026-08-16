package modules

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

var secondOrderPayloads = []string{
	"sxel2nd1'",
	"sxel2nd1'-- ",
	"sxel2nd1\"",
	"sxel2nd1');-- ",
}

func ScanSecondOrderSQLi(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	for _, form := range target.Forms {
		if !strings.EqualFold(form.Method, "POST") {
			continue
		}
		displayPages := displayPages(form.Action, target.URL)
		bl := FetchFormBaseline(client, cfg, form)
		if !bl.Valid {
			continue
		}
		displayBaseline := displayBaseline(client, cfg, displayPages)
		for _, inp := range form.Inputs {
			if cfg.Verbose {
				output.Verbose("[sqli-2nd] form=%s input=%s", form.Action, inp.Name)
			}
			for _, pld := range secondOrderPayloads {
				ev, dbmsBody := secondOrderProbe(client, cfg, form, inp.Name, pld, displayPages, displayBaseline)
				if ev != "" {
					results = append(results, core.ScanResult{
						Type: "SQL Injection (Second-Order via Form)" + dbmsLabel(dbmsBody),
						URL:  form.Action, Method: "POST", Parameter: inp.Name, Payload: pld,
						Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
					})
					output.Warn("Second-Order SQLi: %s input=%s", form.Action, inp.Name)
					break
				}
			}
		}
	}
	return results
}

func displayPages(formAction, pageURL string) []string {
	var pages []string
	seen := map[string]bool{}
	for _, p := range []string{formAction, pageURL} {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		pages = append(pages, p)
	}
	return pages
}

func displayBaseline(client *http.Client, cfg *core.Config, pages []string) map[string]core.BaselineResult {
	out := map[string]core.BaselineResult{}
	for _, p := range pages {
		body, status, err := core.DoGET(client, cfg, p)
		if err != nil {
			continue
		}
		out[p] = core.BaselineResult{
			Body:    body,
			BodyLow: strings.ToLower(body),
			Length:  len(body),
			Status:  status,
			Valid:   true,
		}
	}
	return out
}

func secondOrderProbe(client *http.Client, cfg *core.Config, form core.Form, input, payload string, pages []string, bases map[string]core.BaselineResult) (string, string) {
	d := core.FormDefaults(form)
	d.Set(input, payload)
	if _, _, err := core.DoPOST(client, cfg, form.Action, d); err != nil {
		return "", ""
	}
	var hits []string
	var hitBody string
	for _, p := range pages {
		base, ok := bases[p]
		if !ok {
			continue
		}
		body, _, err := core.DoGET(client, cfg, p)
		if err != nil {
			continue
		}
		if ev := DetectSQLiVsBaseline(body, base); ev != "" {
			hits = append(hits, fmt.Sprintf("%s (%s)", p, ev))
			if hitBody == "" {
				hitBody = body
			}
		}
	}
	if len(hits) > 0 {
		return fmt.Sprintf("stored via POST, error surfaced on display page(s): %s", strings.Join(hits, "; ")), hitBody
	}
	return "", ""
}
