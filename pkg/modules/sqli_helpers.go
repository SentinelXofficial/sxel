package modules

import (
	"fmt"
	"net/http"
	"strings"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/payload"
)

// DetectSQLi checks body for SQL error patterns.
func DetectSQLi(body string) string {
	low := strings.ToLower(body)
	for _, pat := range payload.SQLiErrorPatterns {
		if strings.Contains(low, pat) {
			return fmt.Sprintf("pattern: %q", pat)
		}
	}
	return ""
}

// FetchBaseline retrieves a safe-request baseline for a parameter.
func FetchBaseline(client *http.Client, cfg *core.Config, rawURL, param string) core.BaselineResult {
	safe, _ := core.SetParam(rawURL, param, "1")
	body, status, err := core.DoGET(client, cfg, safe)
	if err != nil {
		return core.BaselineResult{}
	}
	return core.BaselineResult{
		Body:    body,
		BodyLow: strings.ToLower(body),
		Length:  len(body),
		Status:  status,
	}
}

// DetectSQLiVsBaseline only flags errors NOT present in the baseline response.
func DetectSQLiVsBaseline(body string, bl core.BaselineResult) string {
	if bl.BodyLow == "" && bl.Length == 0 {
		return ""
	}
	low := strings.ToLower(body)
	var found []string
	for _, pat := range payload.SQLiErrorPatterns {
		if strings.Contains(low, pat) && !strings.Contains(bl.BodyLow, pat) {
			found = append(found, pat)
		}
	}
	if len(found) == 0 {
		return ""
	}
	if len(found) > 3 {
		found = found[:3]
	}
	return fmt.Sprintf("new error pattern(s): %s", strings.Join(found, " | "))
}

// FetchFormBaseline retrieves a safe baseline from a form submission
// (using default/safe values, no injection payloads) so we can filter
// out error messages that appear even without injection.
func FetchFormBaseline(client *http.Client, cfg *core.Config, form core.Form) core.BaselineResult {
	if form.Method == "POST" {
		body, status, err := core.DoPOST(client, cfg, form.Action, core.FormDefaults(form))
		if err != nil {
			return core.BaselineResult{}
		}
		return core.BaselineResult{
			Body:    body,
			BodyLow: strings.ToLower(body),
			Length:  len(body),
			Status:  status,
		}
	}
	// GET form: submit with default values via query string
	u, _ := core.SetParam(form.Action, "", "1")
	body, status, err := core.DoGET(client, cfg, u)
	if err != nil {
		return core.BaselineResult{}
	}
	return core.BaselineResult{
		Body:    body,
		BodyLow: strings.ToLower(body),
		Length:  len(body),
		Status:  status,
	}
}
