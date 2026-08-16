package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/internal/banner"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/engine"
	"github.com/SentinelXofficial/sxel/pkg/poc"
	"github.com/SentinelXofficial/sxel/pkg/proxy"
)

const pluginRepo = "https://raw.githubusercontent.com/chaitin/xray-plugins/main/poc/manual"

func runGenCA(args []string) {
	fs := flag.NewFlagSet("genca", flag.ExitOnError)
	dir := fs.String("dir", "", "output directory for CA files (default ~/.sxel/ca)")
	fs.Parse(args)
	if *dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			output.Error("home dir: %v", err)
			os.Exit(1)
		}
		*dir = filepath.Join(home, ".sxel", "ca")
	}
	if _, err := proxy.LoadOrCreateCA(*dir); err != nil {
		output.Error("generate CA: %v", err)
		os.Exit(1)
	}
	output.Success("CA certificate: %s", filepath.Join(*dir, "ca.pem"))
	output.Success("CA private key: %s", filepath.Join(*dir, "ca.key"))
	output.Info("Trust ca.pem in your browser/system, then run: sxel proxy")
}

func runPlugin(args []string) {
	fs := flag.NewFlagSet("plugin", flag.ExitOnError)
	dir := fs.String("dir", "./pocs/", "PoC directory to install into")
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Println("Usage: sxel plugin <list|search <kw>|install <name|all>|remove <name|all>> [--dir ./pocs/]")
		os.Exit(1)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		output.Error("mkdir: %v", err)
		os.Exit(1)
	}
	switch fs.Arg(0) {
	case "list":
		names, err := listInstalledPlugins(*dir)
		if err != nil {
			output.Error("list: %v", err)
			os.Exit(1)
		}
		if len(names) == 0 {
			output.Info("no plugins installed in %s", *dir)
			return
		}
		output.Success("%d plugin(s) installed:", len(names))
		for _, n := range names {
			output.Info("  %s", n)
		}
	case "search":
		if fs.NArg() < 2 {
			output.Error("usage: sxel plugin search <keyword>")
			os.Exit(1)
		}
		kw := strings.ToLower(fs.Arg(1))
		names, err := remotePluginNames()
		if err != nil {
			output.Error("search remote: %v", err)
			os.Exit(1)
		}
		var hits []string
		for _, n := range names {
			if strings.Contains(strings.ToLower(n), kw) {
				hits = append(hits, n)
			}
		}
		if len(hits) == 0 {
			output.Info("no remote plugin matches %q", kw)
			return
		}
		output.Success("%d remote plugin(s) match %q:", len(hits), kw)
		for _, n := range hits {
			output.Info("  %s", n)
		}
	case "install":
		if fs.NArg() < 2 {
			output.Error("usage: sxel plugin install <name|all>")
			os.Exit(1)
		}
		names, err := remotePluginNames()
		if err != nil {
			output.Error("fetch remote list: %v", err)
			os.Exit(1)
		}
		want := fs.Arg(1)
		var targets []string
		if want == "all" {
			targets = names
		} else {
			for _, n := range names {
				if n == want || strings.HasPrefix(n, want) {
					targets = append(targets, n)
				}
			}
		}
		if len(targets) == 0 {
			output.Error("no remote plugin matches %q (try: sxel plugin search)", want)
			os.Exit(1)
		}
		ok, fail := 0, 0
		for _, n := range targets {
			if err := installPlugin(*dir, n); err != nil {
				output.Error("install %s: %v", n, err)
				fail++
				continue
			}
			ok++
		}
		output.Success("installed %d plugin(s) into %s (%d failed)", ok, *dir, fail)
	case "remove":
		if fs.NArg() < 2 {
			output.Error("usage: sxel plugin remove <name|all>")
			os.Exit(1)
		}
		names, err := listInstalledPlugins(*dir)
		if err != nil {
			output.Error("list: %v", err)
			os.Exit(1)
		}
		want := fs.Arg(1)
		removed := 0
		for _, n := range names {
			if want != "all" && n != want {
				continue
			}
			if err := os.Remove(filepath.Join(*dir, n)); err == nil {
				removed++
			}
		}
		output.Success("removed %d plugin(s)", removed)
	default:
		fmt.Println("Usage: sxel plugin <list|search <kw>|install <name|all>|remove <name|all>> [--dir ./pocs/]")
		os.Exit(1)
	}
}

func listInstalledPlugins(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func remotePluginNames() ([]string, error) {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/chaitin/xray-plugins/contents/poc/manual", nil)
	req.Header.Set("User-Agent", "sxel")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github api status %d", resp.StatusCode)
	}
	var items []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	var names []string
	for _, it := range items {
		if strings.HasSuffix(it.Name, ".yml") || strings.HasSuffix(it.Name, ".yaml") {
			names = append(names, it.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func installPlugin(dir, name string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(pluginRepo + "/" + url.PathEscape(name))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("remote status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	out := filepath.Join(dir, name)
	return os.WriteFile(out, data, 0o644)
}

func runHTTPFuzzer(args []string) {
	fs := flag.NewFlagSet("httpfuzzer", flag.ExitOnError)
	u := fs.String("u", "", "Target URL with FUZZ marker or --param name")
	wordlist := fs.String("wordlist", "", "Wordlist file (one word per line)")
	param := fs.String("param", "", "Parameter name to fuzz (added to query or body)")
	method := fs.String("m", "GET", "HTTP method (GET/POST)")
	baseline := fs.Bool("baseline", true, "Compare each word against a baseline request")
	threads := fs.Int("threads", 5, "Concurrent requests")
	timeout := fs.Int("timeout", 10, "HTTP timeout (seconds)")
	out := fs.String("o", "", "Save interesting results to JSON file")
	fs.Parse(args)
	if *u == "" || *wordlist == "" {
		output.Error("usage: sxel httpfuzzer -u http://target/FUZZ|?id=FUZZ --wordlist words.txt [--param id] [--baseline]")
		os.Exit(1)
	}
	words, err := readLines(*wordlist)
	if err != nil {
		output.Error("wordlist: %v", err)
		os.Exit(1)
	}
	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	type result struct {
		Word     string `json:"word"`
		Status   int    `json:"status"`
		Length   int    `json:"length"`
		Baseline bool   `json:"baseline_match"`
	}
	results := make([]result, 0, len(words))
	var mu sync.Mutex
	var baseStatus int
	var baseLen int
	if *baseline {
		bs, bl, err := fuzzRequest(client, *u, *param, *method, "")
		if err != nil {
			output.Error("baseline request failed: %v — cannot filter results, aborting (use --baseline=false to fuzz anyway)", err)
			os.Exit(1)
		}
		baseStatus, baseLen = bs, bl
		output.Info("baseline: HTTP %d, %d bytes", bs, bl)
	}
	threadsN := *threads
	if threadsN < 1 {
		threadsN = 1
	}
	sem := make(chan struct{}, threadsN)
	var wg sync.WaitGroup
	for _, w := range words {
		w := w
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			st, ln, err := fuzzRequest(client, *u, *param, *method, w)
			if err != nil {
				return
			}
			if *baseline {
				if baseStatus > 0 && st == baseStatus && ln == baseLen {
					return
				}
			}
			mu.Lock()
			results = append(results, result{Word: w, Status: st, Length: ln})
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Status < results[j].Status })
	if len(results) == 0 {
		output.Info("no interesting results (all words matched baseline)")
		return
	}
	output.Success("%d interesting result(s):", len(results))
	for _, r := range results {
		output.Info("%-30s HTTP %d  %d bytes", r.Word, r.Status, r.Length)
	}
	if *out != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		os.WriteFile(*out, data, 0o644)
		output.Info("saved to %s", *out)
	}
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

func fuzzRequest(client *http.Client, rawURL, param, method, word string) (int, int, error) {
	var body io.Reader
	var target string
	if param != "" {
		q := make(url.Values)
		q.Set(param, word)
		u, err := url.Parse(rawURL)
		if err != nil {
			return 0, 0, err
		}
		if strings.EqualFold(method, "POST") {
			body = strings.NewReader(q.Encode())
		} else {
			uq := u.Query()
			uq.Set(param, word)
			u.RawQuery = uq.Encode()
		}
		target = u.String()
	} else {
		target = strings.ReplaceAll(rawURL, "FUZZ", url.QueryEscape(word))
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return 0, 0, err
	}
	if strings.EqualFold(method, "POST") && param != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, 0, err
	}
	return resp.StatusCode, len(data), nil
}

type apiScanJob struct {
	ID       string            `json:"id"`
	URL      string            `json:"url"`
	Modules  string            `json:"modules"`
	Poc      string            `json:"poc"`
	Status   string            `json:"status"`
	Started  time.Time         `json:"started"`
	Finished time.Time         `json:"finished"`
	Findings []core.ScanResult `json:"findings"`
}

func runHTTP(args []string) {
	fs := flag.NewFlagSet("http", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "API listen address")
	pocDir := fs.String("poc-dir", "./pocs/", "PoC directory for scans")
	fs.Parse(args)

	banner.Print()
	output.Info("HTTP API + dashboard listening on http://%s", *listen)
	output.Info("POST /api/v1/scan {\"url\":\"...\",\"modules\":\"sqli,xss\",\"poc\":\"*\"}")

	jobs := map[string]*apiScanJob{}
	var mu sync.Mutex
	startScan := func(job *apiScanJob, templates []engine.Template, pocs []*poc.PoC) {
		cfg := &core.Config{
			URL:               job.URL,
			Threads:           5,
			Timeout:           30,
			SQLScan:           true,
			XSSScan:           true,
			BlindSQLi:         true,
			MaxQueryVariants:  10,
			HandshakeTimeout:  0,
			SQLiMarginFactor:  0.7,
			SQLiConfirmFactor: 0.6,
			Recorder:          core.NewRecorder(512),
			Session:           core.NewSessionJar(""),
		}
		switch job.Modules {
		case "sqli":
			cfg.SQLScan, cfg.BlindSQLi = true, true
			cfg.XSSScan = false
		case "xss":
			cfg.XSSScan = true
			cfg.SQLScan, cfg.BlindSQLi = false, false
		case "all":
			cfg.AllChecks = true
		case "":
		default:
			output.Error("unknown modules %q (valid: sqli, xss, all)", job.Modules)
			mu.Lock()
			job.Status = "error"
			job.Finished = time.Now()
			mu.Unlock()
			return
		}
		results, _, _ := scanTarget(&http.Client{Timeout: 30 * time.Second}, cfg, job.URL, false, templates, pocs, nil, nil, nil, 0, false)
		mu.Lock()
		job.Findings = results
		job.Status = "done"
		job.Finished = time.Now()
		mu.Unlock()
		output.Success("scan %s done: %d finding(s)", job.ID, len(results))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		var rows string
		order := make([]string, 0, len(jobs))
		for id := range jobs {
			order = append(order, id)
		}
		sort.Strings(order)
		for _, id := range order {
			j := jobs[id]
			sev := "info"
			for _, f := range j.Findings {
				if sevRank(f.Severity) > sevRank(sev) {
					sev = strings.ToLower(f.Severity)
				}
			}
			escURL := html.EscapeString(j.URL)
			escMod := html.EscapeString(j.Modules)
			escSt := html.EscapeString(j.Status)
			rows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>", id, escURL, escMod, escSt, len(j.Findings))
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, dashboardHTML, time.Now().Format(time.RFC3339), rows)
	})
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n := len(jobs)
		var findings int
		for _, j := range jobs {
			findings += len(j.Findings)
		}
		mu.Unlock()
		writeJSON(w, map[string]any{"version": "1.2.0", "uptime": time.Since(startTime()).String(), "jobs": n, "findings": findings})
	})
	mux.HandleFunc("/api/v1/findings", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		var all []core.ScanResult
		for _, j := range jobs {
			all = append(all, j.Findings...)
		}
		mu.Unlock()
		writeJSON(w, all)
	})
	mux.HandleFunc("/api/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			URL     string `json:"url"`
			Modules string `json:"modules"`
			Poc     string `json:"poc"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
			http.Error(w, "bad request: {\"url\":\"...\"}", http.StatusBadRequest)
			return
		}
		job := &apiScanJob{ID: fmt.Sprintf("%d", time.Now().UnixNano()), URL: req.URL, Modules: req.Modules, Poc: req.Poc, Status: "running", Started: time.Now()}
		mu.Lock()
		jobs[job.ID] = job
		mu.Unlock()
		var templates []engine.Template
		var pocs []*poc.PoC
		if req.Poc != "" {
			if pl, err := poc.LoadDir(*pocDir); err == nil {
				pocs = pl
			}
		}
		go startScan(job, templates, pocs)
		writeJSON(w, map[string]any{"id": job.ID, "status": "running"})
	})
	mux.HandleFunc("/api/v1/scan/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/scan/")
		mu.Lock()
		job, ok := jobs[id]
		if !ok {
			mu.Unlock()
			http.NotFound(w, r)
			return
		}
		jobCopy := *job
		mu.Unlock()
		writeJSON(w, &jobCopy)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		output.Error("http api: %v", err)
		os.Exit(1)
	}
}

var apiStart = time.Now()

func startTime() time.Time { return apiStart }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	default:
		return 1
	}
}

const dashboardHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>sxel API dashboard</title>
<style>body{font-family:monospace;background:#111;color:#ddd;padding:20px}h1{color:#4caf50}table{border-collapse:collapse;width:100%%}td,th{border:1px solid #333;padding:6px;text-align:left}th{background:#222}code{color:#8bc34a}</style>
</head><body><h1>sxel — HTTP API dashboard</h1><p>generated at %s</p>
<h2>Scan jobs</h2><table><tr><th>ID</th><th>URL</th><th>Modules</th><th>Status</th><th>Findings</th></tr>%s</table>
<h2>API</h2><ul><li><code>GET /api/v1/status</code></li><li><code>GET /api/v1/findings</code></li><li><code>POST /api/v1/scan</code> body: <code>{"url":"http://host","modules":"sqli|xss|all","poc":"*"}</code></li><li><code>GET /api/v1/scan/&lt;id&gt;</code></li></ul>
</body></html>`
