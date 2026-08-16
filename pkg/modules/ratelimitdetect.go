package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"time"
)

func TestRateLimiting(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult

	burstSize := 30
	concurrency := 5
	if cfg.Threads > 0 {
		concurrency = cfg.Threads
	}

	output.Info("[rate-limit-test] Sending %d requests (%d concurrent)...\n", burstSize, concurrency)

	type outcome struct {
		status int
		err    error
		ms     int64
	}

	var outcomes []outcome
	sem := make(chan struct{}, concurrency)
	resultsCh := make(chan outcome, burstSize)

	for i := 0; i < burstSize; i++ {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			t0 := time.Now()
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				resultsCh <- outcome{err: err}
				return
			}
			core.ApplyHeaders(req, cfg)
			q := req.URL.Query()
			q.Set("_sxel_rl", fmt.Sprintf("%d", time.Now().UnixNano()))
			req.URL.RawQuery = q.Encode()

			resp, err := client.Do(req)
			elapsed := time.Since(t0).Milliseconds()
			if err != nil {
				resultsCh <- outcome{err: err, ms: elapsed}
				return
			}
			core.ReadBody(resp.Body)
			resp.Body.Close()
			resultsCh <- outcome{status: resp.StatusCode, ms: elapsed}
		}()
	}

	for i := 0; i < burstSize; i++ {
		outcomes = append(outcomes, <-resultsCh)
	}

	type validOutcome struct {
		status int
		ms     int64
	}
	var valid []validOutcome
	errored := 0
	for _, o := range outcomes {
		if o.err != nil || o.status == 0 {
			errored++
			continue
		}
		valid = append(valid, validOutcome{status: o.status, ms: o.ms})
	}

	if len(valid) == 0 {
		evidence := fmt.Sprintf("%d/%d requests failed — no valid HTTP status obtained; rate limiting cannot be assessed", errored, burstSize)
		results = append(results, core.ScanResult{
			Type:      "Rate Limiting Assessment",
			URL:       targetURL,
			Method:    "GET (burst)",
			Parameter: fmt.Sprintf("%d requests", burstSize),
			Payload:   fmt.Sprintf("concurrency=%d", concurrency),
			Severity:  "INFO",
			Evidence:  evidence,
			Timestamp: time.Now(),
		})
		output.Info("[rate-limit-test] %d/%d requests errored — cannot assess rate limiting\n", errored, burstSize)
		return results
	}

	var (
		ratelimited  int
		totalMS      int64
		firstStatus  int
		rlAfterValid int
		rlAfterSet   bool
	)

	for i, v := range valid {
		totalMS += v.ms
		if i == 0 {
			firstStatus = v.status
		}
		if v.status == 429 || v.status == 403 || v.status == 503 || v.status == 400 {
			ratelimited++
			if !rlAfterSet {
				rlAfterSet = true
				rlAfterValid = i
			}
		}
	}

	avgMS := totalMS / int64(len(valid))

	severity := "INFO"
	evidence := "No rate limiting detected"

	switch {
	case ratelimited > 0 && firstStatus >= 200 && firstStatus < 400:
		severity = "LOW"
		if rlAfterValid > 0 {
			evidence = fmt.Sprintf("%d/%d requests returned 429/403/503/400 — rate limiting ACTIVE after ~%d requests", ratelimited, burstSize, rlAfterValid)
		} else {
			evidence = fmt.Sprintf("%d/%d requests returned 429/403/503/400 — rate limiting ACTIVE immediately", ratelimited, burstSize)
		}
	case ratelimited > 0:
		severity = "LOW"
		evidence = fmt.Sprintf("%d/%d requests blocked (429/403/503/400) since the first request", ratelimited, burstSize)
	case avgMS > 2000:
		severity = "LOW"
		evidence = fmt.Sprintf("High avg response time (%dms) under burst — possible throttling without explicit 429", avgMS)
	case errored >= burstSize/3:
		severity = "LOW"
		evidence = fmt.Sprintf("%d/%d requests failed — possible IP ban or connection throttling", errored, burstSize)
	}

	results = append(results, core.ScanResult{
		Type:      "Rate Limiting Assessment",
		URL:       targetURL,
		Method:    "GET (burst)",
		Parameter: fmt.Sprintf("%d requests", burstSize),
		Payload:   fmt.Sprintf("concurrency=%d avg=%dms", concurrency, avgMS),
		Severity:  severity,
		Evidence:  evidence,
		Timestamp: time.Now(),
	})

	output.Info("[rate-limit-test] %d requests | %d rate-limited | avg %dms | first HTTP %d\n", burstSize, ratelimited, avgMS, firstStatus)

	return results
}
