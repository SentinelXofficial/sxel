package modules

import (
	"net/http"
	"sync"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/engine"
)

// ScanStrobe is the full adaptive deep-dive pipeline.
// It combines: fingerprinting → module selection → attack chains → template scanning
// in one automated pass, adapting to what it discovers.
func ScanStrobe(client *http.Client, cfg *core.Config, target core.CrawlResult, templates []engine.Template) []core.ScanResult {
	var allResults []core.ScanResult
	var mu sync.Mutex

	output.Info("Strobe: adaptive deep-dive on %s", target.URL)

	// Phase 1: Recon — discover the target
	body, status, err := core.DoGET(client, cfg, target.URL)
	if err != nil || status == 0 {
		return nil
	}

	// Fingerprint
	headers := extractResponseHeaders(client, cfg, target.URL)
	fp := engine.FingerprintTarget(body, headers, target.URL)

	output.Info("Strobe: detected %v", fp.Tech)
	if fp.IsAPI {
		output.Info("Strobe: API endpoint detected")
	}
	if fp.HasLogin {
		output.Info("Strobe: login form detected")
	}

	// Phase 2: Smart scan — only relevant modules
	type scanJob struct {
		name string
		fn   func(*http.Client, *core.Config, core.CrawlResult) []core.ScanResult
	}

	var jobs []scanJob
	add := func(name string, fn func(*http.Client, *core.Config, core.CrawlResult) []core.ScanResult) {
		if engine.ShouldScan(name, fp) {
			jobs = append(jobs, scanJob{name, fn})
		}
	}

	add("sqli", ScanSQLi)
	add("xss", ScanXSS)
	if engine.ShouldScan("ssrf", fp) {
		add("ssrf", ScanSSRF)
	}
	if engine.ShouldScan("cmdi", fp) {
		add("cmdi", ScanCmdInjection)
	}
	if engine.ShouldScan("lfi", fp) {
		add("lfi", ScanLFI)
	}
	if engine.ShouldScan("xxe", fp) {
		add("xxe", ScanXXE)
	}
	if engine.ShouldScan("nosql", fp) {
		add("nosql", ScanNoSQLi)
	}
	if engine.ShouldScan("jwt", fp) {
		add("jwt", ScanJWT)
	}
	if engine.ShouldScan("idor", fp) {
		add("idor", ScanIDOR)
	}
	if engine.ShouldScan("fileupload", fp) {
		add("fileupload", ScanFileUpload)
	}
	if engine.ShouldScan("csrf", fp) {
		jobs = append(jobs, scanJob{"csrf", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return ScanCSRF(cf, t)
		}})
	}

	output.Info("Strobe: running %d relevant module(s) (filtered from full set)", len(jobs))

	// Run all relevant jobs concurrently
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(job scanJob) {
			defer wg.Done()
			defer func() { <-sem }()
			res := job.fn(client, cfg, target)
			if len(res) > 0 {
				mu.Lock()
				allResults = append(allResults, res...)
				mu.Unlock()
			}
		}(j)
	}
	wg.Wait()

	// Phase 3: Template engine
	if len(templates) > 0 {
		allResults = append(allResults, engine.RunTemplates(client, cfg, target.URL, templates)...)
	}

	// Phase 4: If nothing found, try attack chains
	if len(allResults) == 0 && fp.HasLogin {
		chainResults := engine.ChainLoginBypass(client, cfg, target.URL)
		allResults = append(allResults, chainResults...)
	}

	output.Info("Strobe: complete — %d finding(s)", len(allResults))
	return allResults
}

func extractResponseHeaders(client *http.Client, cfg *core.Config, targetURL string) map[string]string {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}
	core.ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	headers := make(map[string]string)
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}
	return headers
}
