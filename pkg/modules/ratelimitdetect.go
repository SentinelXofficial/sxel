package modules

import (
	"github.com/SentinelXofficial/sxel/pkg/core"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TestRateLimiting sends a burst of rapid requests to the target and measures
// whether the server rate-limits after a threshold. Useful for bug bounty prep
// to know what the target tolerates before locking you out.
func TestRateLimiting(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult

	burstSize := 30
	concurrency := 5
	if cfg.Threads > 0 {
		concurrency = cfg.Threads
	}

	fmt.Printf("  \033[36m[rate-limit-test] Sending %d requests (%d concurrent)...\033[0m\n", burstSize, concurrency)

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
			// Avoid caching by adding a unique query param
			q := req.URL.Query()
			q.Set("_sxsc_rl", fmt.Sprintf("%d", time.Now().UnixNano()))
			req.URL.RawQuery = q.Encode()

			resp, err := client.Do(req)
			elapsed := time.Since(t0).Milliseconds()
			if err != nil {
				resultsCh <- outcome{err: err, ms: elapsed}
				return
			}
			io.ReadAll(resp.Body) //nolint:errcheck
			resp.Body.Close()
			resultsCh <- outcome{status: resp.StatusCode, ms: elapsed}
		}()
	}

	// Collect
	for i := 0; i < burstSize; i++ {
		outcomes = append(outcomes, <-resultsCh)
	}

	// ── Analyze ──────────────────────────────────────────────────────────────
	var (
		ratelimited int
		errored     int
		totalMS     int64
		firstStatus int
	)

	for i, o := range outcomes {
		if o.err != nil {
			errored++
			continue
		}
		totalMS += o.ms
		if i == 0 {
			firstStatus = o.status
		}
		if o.status == 429 || o.status == 503 {
			ratelimited++
		}
	}

	avgMS := int64(0)
	if len(outcomes)-errored > 0 {
		avgMS = totalMS / int64(len(outcomes)-errored)
	}

	severity := "INFO"
	evidence := "No rate limiting detected"

	if ratelimited > 0 {
		severity = "LOW"
		evidence = fmt.Sprintf("%d/%d requests returned 429/503 — rate limiting ACTIVE after ~%d requests", ratelimited, burstSize, burstSize-ratelimited)
	} else if avgMS > 2000 {
		severity = "LOW"
		evidence = fmt.Sprintf("High avg response time (%dms) under burst — possible throttling without explicit 429", avgMS)
	} else if errored >= burstSize/3 {
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

	fmt.Printf("  \033[36m[rate-limit-test]\033[0m %d requests | %d rate-limited | avg %dms | first HTTP %d\n",
		burstSize, ratelimited, avgMS, firstStatus)

	return results
}
