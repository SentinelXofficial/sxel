package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

var ldapErrRe = regexp.MustCompile(`(?i)(invalid dn|ldap[^"']{0,40}(error|filter)|unable to parse|filter compilation|no such object|object class violation|malformed filter|invalid search filter)`)
var xpathErrRe = regexp.MustCompile(`(?i)(invalid xpath|xpath error|syntax error in xpath|failed to compile xpath|unable to evaluate|inappropriate argument)`)

type ldapXPathPair struct {
	engine string
	trueP  string
	falseP string
}

var ldapXPathPairs = []ldapXPathPair{
	{"LDAP", `*)(|(uid=*))(|(uid=*`, `*)(|(uid=zzzz_nothing))(|(uid=zzzz_nothing`},
	{"LDAP", `*)(uid=*))(|(uid=*`, `*)(uid=zzzz_nothing))(|(uid=zzzz_nothing`},
	{"XPath", `' or '1'='1`, `' or '1'='2`},
	{"XPath", `' or 1=1 or ''='`, `' or 1=2 or ''='`},
}

func ScanLDAPXPath(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	p, perr := url.Parse(target.URL)
	var params url.Values
	if perr == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	}
	for param := range params {
		var splits []boolSplit
		errored := false
		baselineBody := ""
		if baseReq, berr := core.SetParam(target.URL, param, "1"); berr == nil {
			if bb, _, e := core.DoGET(client, cfg, baseReq); e == nil {
				baselineBody = bb
			}
		}
		for _, pair := range ldapXPathPairs {
			uTrue, err := core.SetParam(target.URL, param, pair.trueP)
			if err != nil {
				break
			}
			bTrue, sTrue, err := core.DoGET(client, cfg, uTrue)
			if err != nil {
				continue
			}
			if (ldapErrRe.MatchString(bTrue) && !ldapErrRe.MatchString(baselineBody)) ||
				(xpathErrRe.MatchString(bTrue) && !xpathErrRe.MatchString(baselineBody)) {
				results = append(results, core.ScanResult{
					Type: "LDAP/XPath error leak",
					URL:  target.URL, Method: "GET", Parameter: param,
					Payload: pair.trueP, Severity: "LOW",
					Evidence:  "server exposed a filter/query error message",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [LDX] %s param=%s error leak (%s)\n", target.URL, param, pair.engine)
				errored = true
				break
			}
			uFalse, err := core.SetParam(target.URL, param, pair.falseP)
			if err != nil {
				break
			}
			bFalse, sFalse, err := core.DoGET(client, cfg, uFalse)
			if err != nil {
				continue
			}
			diff := len(bTrue) - len(bFalse)
			splits = append(splits, boolSplit{diff: diff, significant: diff > 100 || diff < -100 || sTrue != sFalse})
		}
		if errored {
			continue
		}
		if consistentClassSplit(splits) {
			results = append(results, core.ScanResult{
				Type: "LDAP/XPath injection (boolean)",
				URL:  target.URL, Method: "GET", Parameter: param,
				Payload: "multiple true/false variant class split", Severity: "HIGH",
				Evidence:  "consistent class split across independent true/false variant pairs",
				Timestamp: time.Now(),
			})
			fmt.Printf("  [LDX] %s param=%s boolean split\n", target.URL, param)
		}
	}

	for _, form := range target.Forms {
		if strings.ToUpper(form.Method) != "POST" || len(form.Inputs) == 0 {
			continue
		}
		for _, inp := range form.Inputs {
			var splits []boolSplit
			for _, p := range ldapXPathPairs {
				d := core.FormDefaults(form)
				d.Set(inp.Name, p.trueP)
				bTrue, sTrue, err1 := core.DoPOST(client, cfg, form.Action, d)
				d.Set(inp.Name, p.falseP)
				bFalse, sFalse, err2 := core.DoPOST(client, cfg, form.Action, d)
				if err1 != nil || err2 != nil {
					continue
				}
				if ldapErrRe.MatchString(bTrue) || xpathErrRe.MatchString(bTrue) {
					results = append(results, core.ScanResult{
						Type: "LDAP/XPath error leak",
						URL:  form.Action, Method: "POST", Parameter: inp.Name,
						Payload: p.trueP, Severity: "LOW",
						Evidence:  "server exposed a filter/query error message",
						Timestamp: time.Now(),
					})
					fmt.Printf("  [LDX] %s param=%s error leak (%s)\n", form.Action, inp.Name, p.engine)
					break
				}
				diff := len(bTrue) - len(bFalse)
				splits = append(splits, boolSplit{diff: diff, significant: diff > 100 || diff < -100 || sTrue != sFalse})
			}
			if consistentClassSplit(splits) {
				results = append(results, core.ScanResult{
					Type: "LDAP/XPath injection (boolean)",
					URL:  form.Action, Method: "POST", Parameter: inp.Name,
					Payload: "multiple true/false variant class split", Severity: "HIGH",
					Evidence:  "consistent class split across independent true/false variant pairs",
					Timestamp: time.Now(),
				})
				fmt.Printf("  [LDX] %s param=%s boolean split\n", form.Action, inp.Name)
			}
		}
	}
	return results
}
