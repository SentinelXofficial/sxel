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

const (
	unionMaxCols           = 8
	maxUnionProbesPerInput = 300
)

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
		stripped = append(stripped, normalizeSQLiBody(body, []string{marker}))
	}
	if stripped[0] != stripped[1] {
		return "", false
	}
	return stripped[0], true
}

func unionURLProbe(client *http.Client, cfg *core.Config, targetURL, param string, v unionVariant, n, changeCol int) (bool, int, int) {
	probe, control, markerP, markerC := unionPair(v, n, changeCol)
	bodyA, ok := unionResponseStable(client, cfg, targetURL, param, probe, markerP)
	if !ok {
		return false, 0, 0
	}
	bodyB, ok := unionResponseStable(client, cfg, targetURL, param, control, markerC)
	if !ok {
		return false, 0, 0
	}
	if bodyA == bodyB {
		return false, 0, 0
	}
	return true, len(bodyA), len(bodyB)
}

func scanUnionURL(client *http.Client, cfg *core.Config, targetURL, param string) []core.ScanResult {
	var results []core.ScanResult
	bl := FetchBaseline(client, cfg, targetURL, param)
	if !bl.Valid {
		return nil
	}
	probes := 0
variants:
	for _, v := range unionVariants() {
		for n := 1; n <= unionMaxCols; n++ {
			for changeCol := 1; changeCol <= n; changeCol++ {
				if probes >= maxUnionProbesPerInput {
					return results
				}
				probes++
				ok, l1, l2 := unionURLProbe(client, cfg, targetURL, param, v, n, changeCol)
				if !ok {
					continue
				}
				if n < unionMaxCols {
					conf, _, _ := unionURLProbe(client, cfg, targetURL, param, v, n+1, 1)
					if conf {
						if cfg.Verbose {
							output.Verbose("[sqli-union] %s param=%s variant %q cols=%d not exact (cols=%d also differs) — noise, skipping variant", targetURL, param, v.quote+v.comment, n, n+1)
						}
						continue variants
					}
				}
				probe, control, _, _ := unionPair(v, n, changeCol)
				results = append(results, core.ScanResult{
					Type: fmt.Sprintf("SQL Injection Union-Based (%d columns)", n),
					URL:  targetURL, Method: "GET", Parameter: param,
					Payload:   fmt.Sprintf("%s | control: %s", probe, control),
					Severity:  "HIGH",
					Evidence:  fmt.Sprintf("probe/control responses differ after marker-strip (col %d, %d vs %d bytes, baseline %d bytes)", changeCol, l1, l2, bl.Length),
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
	sent := 0
	submit := func(payload string) (string, bool) {
		if sent >= maxUnionProbesPerInput*4 {
			return "", false
		}
		sent++
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

	unionFormProbe := func(v unionVariant, n, changeCol int) (bool, int, int) {
		probe, control, markerP, markerC := unionPair(v, n, changeCol)
		b1, ok := submit(probe)
		if !ok {
			return false, 0, 0
		}
		b2, ok := submit(control)
		if !ok {
			return false, 0, 0
		}
		b3, ok := submit(probe)
		if !ok {
			return false, 0, 0
		}
		b4, ok := submit(control)
		if !ok {
			return false, 0, 0
		}
		a1 := normalizeSQLiBody(b1, []string{markerP})
		if a1 != normalizeSQLiBody(b3, []string{markerP}) {
			return false, 0, 0
		}
		a2 := normalizeSQLiBody(b2, []string{markerC})
		if a2 != normalizeSQLiBody(b4, []string{markerC}) {
			return false, 0, 0
		}
		if a1 == a2 {
			return false, 0, 0
		}
		return true, len(a1), len(a2)
	}

variants:
	for _, v := range unionVariants() {
		for n := 1; n <= unionMaxCols; n++ {
			for changeCol := 1; changeCol <= n; changeCol++ {
				ok, l1, l2 := unionFormProbe(v, n, changeCol)
				if !ok {
					continue
				}
				if n < unionMaxCols {
					conf, _, _ := unionFormProbe(v, n+1, 1)
					if conf {
						if cfg.Verbose {
							output.Verbose("[sqli-union] %s input=%s variant %q cols=%d not exact (cols=%d also differs) — noise, skipping variant", form.Action, input, v.quote+v.comment, n, n+1)
						}
						continue variants
					}
				}
				probe, control, _, _ := unionPair(v, n, changeCol)
				results = append(results, core.ScanResult{
					Type: fmt.Sprintf("SQL Injection Union-Based via Form (%d columns)", n),
					URL:  form.Action, Method: form.Method, Parameter: input,
					Payload:   fmt.Sprintf("%s | control: %s", probe, control),
					Severity:  "HIGH",
					Evidence:  fmt.Sprintf("probe/control responses differ after marker-strip (col %d, %d vs %d bytes, baseline %d bytes)", changeCol, l1, l2, bl.Length),
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
