package modules

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

// ScanClutch detects race condition / TOCTOU vulnerabilities by sending
// multiple concurrent requests to state-changing endpoints and checking
// if more than one succeeds.
func ScanClutch(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// Identify state-changing endpoints (POST/PUT/DELETE/PATCH forms)
	for _, form := range target.Forms {
		method := strings.ToUpper(form.Method)
		if method != "POST" && method != "PUT" && method != "DELETE" && method != "PATCH" {
			continue
		}

		action := form.Action
		if action == "" {
			action = target.URL
		}

		burstSize := 20
		if cfg.Threads > 0 && cfg.Threads < burstSize {
			burstSize = cfg.Threads * 4
		}

		// Build the baseline request body
		data := core.FormDefaults(form)

		// Send burst of concurrent requests
		type burstResult struct {
			status int
			body   string
			len    int
			err    error
		}

		var wg sync.WaitGroup
		resultsCh := make(chan burstResult, burstSize)
		start := time.Now()

		for i := 0; i < burstSize; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, err := http.NewRequest(method, action, bytes.NewBufferString(data.Encode()))
				if err != nil {
					resultsCh <- burstResult{err: err}
					return
				}
				core.ApplyHeaders(req, cfg)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				resp, err := client.Do(req)
				if err != nil {
					resultsCh <- burstResult{err: err}
					return
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				resultsCh <- burstResult{
					status: resp.StatusCode,
					body:   string(body),
					len:    len(body),
				}
			}()
		}
		wg.Wait()
		close(resultsCh)

		var outcomes []burstResult
		for r := range resultsCh {
			outcomes = append(outcomes, r)
		}

		// Analyze: count successes (2xx) vs failures
		successes := 0
		var firstSuccessBody string
		var firstSuccessStatus int
		for _, o := range outcomes {
			if o.status >= 200 && o.status < 300 {
				successes++
				if firstSuccessBody == "" {
					firstSuccessBody = o.body
					firstSuccessStatus = o.status
				}
			}
		}

		// Race condition detected: multiple successes from a single-use endpoint
		if successes > 1 {
			// Check if responses are meaningfully different (not all identical)
			responseSet := make(map[string]int)
			for _, o := range outcomes {
				if o.status >= 200 && o.status < 300 {
					key := fmt.Sprintf("%d:%d", o.status, o.len)
					responseSet[key]++
				}
			}

			evidence := fmt.Sprintf("%d/%d concurrent requests succeeded (%.0f%%) — potential race condition / TOCTOU",
				successes, burstSize, float64(successes)/float64(burstSize)*100)

			if len(responseSet) > 1 {
				evidence += fmt.Sprintf(" | %d distinct response patterns detected", len(responseSet))
			}

			elapsed := time.Since(start)
			results = append(results, core.ScanResult{
				Type:      "Race Condition / TOCTOU",
				URL:       action,
				Method:    method,
				Parameter: "burst",
				Payload:   fmt.Sprintf("%d concurrent requests in %v", burstSize, elapsed.Round(time.Millisecond)),
				Severity:  "HIGH",
				Evidence:  evidence,
				Timestamp: time.Now(),
				Extra: map[string]string{
					"burst_size":      fmt.Sprintf("%d", burstSize),
					"success_count":   fmt.Sprintf("%d", successes),
					"first_status":    fmt.Sprintf("%d", firstSuccessStatus),
					"response_patterns": fmt.Sprintf("%d", len(responseSet)),
				},
			})
		}
	}

	return results
}
