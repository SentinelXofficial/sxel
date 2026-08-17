package modules

import (
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/payload"
)

var valueAttrRe = regexp.MustCompile(`(?i)\bvalue\s*=\s*"[^"]*"|\bvalue\s*=\s*'[^']*'`)

func normalizeSQLiBody(body string, markers []string) string {
	out := valueAttrRe.ReplaceAllString(body, `value=""`)
	out = html.UnescapeString(out)
	for _, m := range markers {
		if m != "" {
			out = strings.ReplaceAll(out, m, "")
		}
	}
	return out
}

func DetectSQLi(body string) string {
	low := strings.ToLower(body)
	for _, pat := range payload.SQLiErrorPatterns {
		if strings.Contains(low, pat) {
			return fmt.Sprintf("pattern: %q", pat)
		}
	}
	return ""
}

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
		Valid:   true,
	}
}

func DetectSQLiVsBaseline(body string, bl core.BaselineResult) string {
	if !bl.Valid {
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
			Valid:   true,
		}
	}
	u, _ := core.SetFormParams(form.Action, core.FormDefaults(form))
	body, status, err := core.DoGET(client, cfg, u)
	if err != nil {
		return core.BaselineResult{}
	}
	return core.BaselineResult{
		Body:    body,
		BodyLow: strings.ToLower(body),
		Length:  len(body),
		Status:  status,
		Valid:   true,
	}
}
