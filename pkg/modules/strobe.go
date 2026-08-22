package modules

import (
	"io"
	"net/http"
	"sync"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/engine"
)

func ScanStrobe(client *http.Client, cfg *core.Config, target core.CrawlResult, templates []engine.Template) []core.ScanResult {
	var allResults []core.ScanResult
	var mu sync.Mutex

	output.Info("Strobe: adaptive deep-dive on %s", target.URL)

	body, status, err := core.DoGET(client, cfg, target.URL)
	if err != nil || status == 0 {
		return nil
	}

	headers := ExtractResponseHeaders(client, cfg, target.URL)
	fp := engine.FingerprintTarget(body, headers, target.URL)

	output.Info("Strobe: detected %v", fp.Tech)
	if fp.IsAPI {
		output.Info("Strobe: API endpoint detected")
	}
	if fp.HasLogin {
		output.Info("Strobe: login form detected")
	}

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
		jobs = append(jobs, scanJob{"csrf", ScanCSRF})
	}

	output.Info("Strobe: running %d relevant module(s) (filtered from full set)", len(jobs))

	var wg sync.WaitGroup
	threads := cfg.Threads
	if threads < 1 {
		threads = 1
	}
	sem := make(chan struct{}, threads)
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

	if len(templates) > 0 {
		filtered := engine.FilterTemplatesByTech(templates, fp.Tech)
		if len(filtered) > 0 {
			output.Info("Strobe: running %d/%d template(s) for detected tech %v", len(filtered), len(templates), fp.Tech)
			allResults = append(allResults, engine.RunTemplates(client, cfg, target.URL, filtered)...)
		}
	}

	if len(allResults) == 0 && fp.HasLogin {
		chainResults := engine.ChainLoginBypass(client, cfg, target.URL)
		allResults = append(allResults, chainResults...)
	}

	output.Info("Strobe: complete — %d finding(s)", len(allResults))
	return allResults
}

func ExtractResponseHeaders(client *http.Client, cfg *core.Config, targetURL string) map[string]string {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}
	core.ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	// Drain a small amount before closing so keep-alive connections can be
	// reused instead of torn down.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	headers := make(map[string]string)
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}
	return headers
}
