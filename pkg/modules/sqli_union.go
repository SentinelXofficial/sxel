package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

const unionMaxCols = 8

type unionVariant struct {
	quote   string
	comment string
	suffix  string
}

func unionVariants() []unionVariant {
	return []unionVariant{
		{"'", "-- ", ""},
		{"'", "#", ""},
		{"", "-- ", ""},
		{"\"", "-- ", ""},
		{"')", "-- ", ""},
		{"1", "-- ", ""},
		{"'", "-- ", " FROM dual"},
	}
}

func unionPair(v unionVariant, n int, changeCol int) (probe, control, markerProbe, markerControl string) {
	run := func(last int) string {
		parts := make([]string, n)
		for i := 1; i <= n; i++ {
			if i == changeCol {
				parts[i-1] = strconv.Itoa(last)
			} else {
				parts[i-1] = strconv.Itoa(i)
			}
		}
		return "UNION SELECT " + strings.Join(parts, ",") + v.suffix
	}
	last := n + 1
	probe = v.quote + run(n) + v.comment
	control = v.quote + run(last) + v.comment
	return probe, control, run(n), run(last)
}

func unionResponseStable(client *http.Client, cfg *core.Config, rawURL, param, payload, marker string) (string, bool) {
	var stripped []string
	for i := 0; i < 2; i++ {
		u, err := core.SetParam(rawURL, param, payload)
		if err != nil {
			return "", false
		}
		body, _, err := core.DoGET(client, cfg, u)
		if err != nil {
			return "", false
		}
		if hasRateLimitOrError(body) {
			return "", false
		}
		stripped = append(stripped, strings.ReplaceAll(body, marker, ""))
	}
	if stripped[0] != stripped[1] {
		return "", false
	}
	return stripped[0], true
}

func scanUnionURL(client *http.Client, cfg *core.Config, targetURL, param string) []core.ScanResult {
	var results []core.ScanResult
	bl := FetchBaseline(client, cfg, targetURL, param)
	if !bl.Valid {
		return nil
	}
	for _, v := range unionVariants() {
		for n := 1; n <= unionMaxCols; n++ {
			for changeCol := 1; changeCol <= n; changeCol++ {
				probe, control, markerP, markerC := unionPair(v, n, changeCol)
				bodyA, ok := unionResponseStable(client, cfg, targetURL, param, probe, markerP)
				if !ok {
					continue
				}
				bodyB, ok := unionResponseStable(client, cfg, targetURL, param, control, markerC)
				if !ok {
					continue
				}
				if bodyA == bodyB {
					continue
				}
				results = append(results, core.ScanResult{
					Type: fmt.Sprintf("SQL Injection Union-Based (%d columns)", n),
					URL:  targetURL, Method: "GET", Parameter: param,
					Payload:   fmt.Sprintf("%s | control: %s", probe, control),
					Severity:  "HIGH",
					Evidence:  fmt.Sprintf("probe/control responses differ after marker-strip (col %d, %d vs %d bytes, baseline %d bytes)", changeCol, len(bodyA), len(bodyB), bl.Length),
					Timestamp: time.Now(),
				})
				output.Warn("Union-Based SQLi: param=%s cols=%d col%d %q", param, n, changeCol, v.quote+v.comment)
				return results
			}
		}
	}
	return results
}

func scanUnionForm(client *http.Client, cfg *core.Config, form core.Form, input string) []core.ScanResult {
	var results []core.ScanResult
	bl := FetchFormBaseline(client, cfg, form)
	if !bl.Valid {
		return nil
	}
	submit := func(payload string) (string, bool) {
		d := core.FormDefaults(form)
		d.Set(input, payload)
		if form.Method == "POST" {
			body, _, err := core.DoPOST(client, cfg, form.Action, d)
			if err != nil {
				return "", false
			}
			return body, !hasRateLimitOrError(body)
		}
		u, _ := core.SetFormParams(form.Action, d)
		body, _, err := core.DoGET(client, cfg, u)
		if err != nil {
			return "", false
		}
		return body, !hasRateLimitOrError(body)
	}

	for _, v := range unionVariants() {
		for n := 1; n <= unionMaxCols; n++ {
			for changeCol := 1; changeCol <= n; changeCol++ {
				probe, control, markerP, markerC := unionPair(v, n, changeCol)
				b1, ok := submit(probe)
				if !ok {
					continue
				}
				b2, ok := submit(control)
				if !ok {
					continue
				}
				b3, ok := submit(probe)
				if !ok {
					continue
				}
				a1 := strings.ReplaceAll(b1, markerP, "")
				if a1 != strings.ReplaceAll(b3, markerP, "") {
					continue
				}
				a2 := strings.ReplaceAll(b2, markerC, "")
				if a1 == a2 {
					continue
				}
				results = append(results, core.ScanResult{
					Type: fmt.Sprintf("SQL Injection Union-Based via Form (%d columns)", n),
					URL:  form.Action, Method: form.Method, Parameter: input,
					Payload:   fmt.Sprintf("%s | control: %s", probe, control),
					Severity:  "HIGH",
					Evidence:  fmt.Sprintf("probe/control responses differ after marker-strip (col %d, %d vs %d bytes, baseline %d bytes)", changeCol, len(a1), len(a2), bl.Length),
					Timestamp: time.Now(),
				})
				output.Warn("Union-Based SQLi (Form): %s input=%s cols=%d", form.Action, input, n)
				return results
			}
		}
	}
	return results
}

func ScanUnionSQLi(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
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
			output.Verbose("[sqli-union] param=%s", param)
		}
		results = append(results, scanUnionURL(client, cfg, target.URL, param)...)
	}

	for _, form := range target.Forms {
		for _, inp := range form.Inputs {
			if cfg.Verbose {
				output.Verbose("[sqli-union] form %s input=%s", form.Method, inp.Name)
			}
			results = append(results, scanUnionForm(client, cfg, form, inp.Name)...)
		}
	}
	return results
}
