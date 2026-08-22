package modules

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func ScanClutch(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

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
		if cfg.Threads > 0 {
			// Scale down only — never let a small --threads value produce a
			// burst LARGER than the default.
			if scaled := cfg.Threads * 4; scaled < burstSize {
				burstSize = scaled
			}
		}

		fmt.Printf("  [CLUTCH] ⚠ Sending %d concurrent submissions to %s — may create real data on target\n", burstSize, action)

		data := core.FormDefaults(form)

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
				body := core.ReadBody(resp.Body)
				resp.Body.Close()
				resultsCh <- burstResult{
					status: resp.StatusCode,
					body:   body,
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

		successes := 0
		var firstSuccessStatus int
		successBodies := make(map[string]bool)
		hasErrorStatus := false
		for _, o := range outcomes {
			if o.status >= 200 && o.status < 300 {
				successes++
				successBodies[normalizeRaceBody(o.body)] = true
				if firstSuccessStatus == 0 {
					firstSuccessStatus = o.status
				}
			}
			if o.status >= 400 {
				hasErrorStatus = true
			}
		}

		var evidence string
		if len(successBodies) >= 2 {
			controlBurst := distinctBodies(client, cfg, action, method, data, burstSize)
			if len(successBodies) > controlBurst {
				evidence = fmt.Sprintf("%d/%d concurrent requests succeeded with %d distinct response bodies (control burst %d) — inconsistent state handling suggests a race condition / TOCTOU",
					successes, burstSize, len(successBodies), controlBurst)
			}
		} else if successes >= 1 && hasErrorStatus {
			evidence = fmt.Sprintf("%d/%d concurrent requests succeeded while others returned 4xx/5xx (%.0f%%) — inconsistent state handling suggests a race condition / TOCTOU",
				successes, burstSize, float64(successes)/float64(burstSize)*100)
		}

		if evidence != "" {
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
					"burst_size":        fmt.Sprintf("%d", burstSize),
					"success_count":     fmt.Sprintf("%d", successes),
					"first_status":      fmt.Sprintf("%d", firstSuccessStatus),
					"distinct_bodies":   fmt.Sprintf("%d", len(successBodies)),
					"has_error_status":  fmt.Sprintf("%v", hasErrorStatus),
					"response_patterns": fmt.Sprintf("%d", len(successBodies)),
				},
			})
		}
	}

	return results
}

func normalizeRaceBody(body string) string {
	var b strings.Builder
	inToken := false
	tokenLen := 0
	for _, r := range body {
		alnum := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if alnum {
			inToken = true
			tokenLen++
			continue
		}
		if inToken {
			if tokenLen >= 6 {
				b.WriteByte('#')
			} else {
				b.WriteString(strings.Repeat("x", tokenLen))
			}
			inToken = false
			tokenLen = 0
		}
		b.WriteRune(r)
	}
	if inToken {
		if tokenLen >= 6 {
			b.WriteByte('#')
		} else {
			b.WriteString(strings.Repeat("x", tokenLen))
		}
	}
	return b.String()
}

func distinctBodies(client *http.Client, cfg *core.Config, action, method string, data url.Values, n int) int {
	var wg sync.WaitGroup
	ch := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(method, action, bytes.NewBufferString(data.Encode()))
			if err != nil {
				return
			}
			core.ApplyHeaders(req, cfg)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body := core.ReadBody(resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				ch <- normalizeRaceBody(body)
			}
		}()
	}
	wg.Wait()
	close(ch)
	seen := map[string]bool{}
	for s := range ch {
		seen[s] = true
	}
	return len(seen)
}
