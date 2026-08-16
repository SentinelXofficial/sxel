package modules

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

var storedXSSPayloads = []string{
	"<img src=x onerror=alert(1)>",
	"<svg onload=alert(1)>",
	"\" autofocus onfocus=alert(1) x=\"",
	"' autofocus onfocus=alert(1) x='",
	"<script>alert(1)</script>",
}

func storedXSSExecutable(body, payload string) bool {
	ctx, exec := analyzeXSSContext(body, payload)
	return exec && ctx != ""
}

func storedXSSEncoded(body, payload string) bool {
	for _, enc := range []string{html.EscapeString(payload), strings.ReplaceAll(payload, "'", "&#39;"), strings.ReplaceAll(payload, "\"", "&quot;")} {
		if strings.Contains(body, enc) {
			return true
		}
	}
	return false
}

func ScanStoredXSS(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	for _, form := range target.Forms {
		if form.Method != "POST" {
			continue
		}
		pages := displayPages(form.Action, target.URL)
		for _, inp := range form.Inputs {
			if cfg.Verbose {
				output.Verbose("[xss-stored] form=%s input=%s", form.Action, inp.Name)
			}
			bases := displayBaseline(client, cfg, pages)
			for _, pld := range storedXSSPayloads {
				ev := storedXSSProbe(client, cfg, form, inp.Name, pld, pages, bases)
				if ev != "" {
					results = append(results, core.ScanResult{
						Type: "Stored XSS via Form", URL: form.Action,
						Method: "POST", Parameter: inp.Name, Payload: pld,
						Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
					})
					output.Warn("Stored XSS: %s input=%s", form.Action, inp.Name)
					break
				}
			}
		}
	}
	return results
}

func storedXSSProbe(client *http.Client, cfg *core.Config, form core.Form, input, payload string, pages []string, bases map[string]core.BaselineResult) string {
	d := core.FormDefaults(form)
	d.Set(input, payload)
	if _, _, err := core.DoPOST(client, cfg, form.Action, d); err != nil {
		return ""
	}
	var hits []string
	for _, p := range pages {
		base, ok := bases[p]
		if !ok || containsStoredPayload(base.Body, payload) {
			continue
		}
		body, _, err := core.DoGET(client, cfg, p)
		if err != nil {
			continue
		}
		if storedXSSExecutable(body, payload) {
			hits = append(hits, p)
		}
	}
	if len(hits) > 0 {
		return fmt.Sprintf("payload stored via POST and reflected in executable context on display page(s): %s", strings.Join(hits, "; "))
	}
	return ""
}

func containsStoredPayload(baseBody, payload string) bool {
	if strings.Contains(baseBody, payload) {
		return true
	}
	return storedXSSEncoded(baseBody, payload)
}
