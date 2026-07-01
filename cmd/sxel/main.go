package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SentinelXofficial/sxel/internal/banner"
	"github.com/SentinelXofficial/sxel/internal/updater"
	"github.com/SentinelXofficial/sxel/internal/version"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/engine"
	"github.com/SentinelXofficial/sxel/pkg/modules"
)

func main() {
	u := flag.String("u", "", "Target URL, e.g. http://site.com/page?id=1")
	ulong := flag.String("url", "", "Same as -u")
	listFlag := flag.String("list", "", "File with target URLs, one per line")
	listShort := flag.String("l", "", "Same as --list")
	listConcurrency := flag.Int("list-concurrency", 3, "Targets to scan concurrently when using --list")
	crawl := flag.Bool("crawl", false, "Deep recursive crawl")
	basicCrawl := flag.Bool("basic-crawl", false, "Shallow crawl (depth=1)")
	depth := flag.Int("depth", 3, "Max crawl depth")
	threads := flag.Int("threads", 5, "Concurrent scan threads")
	timeout := flag.Int("timeout", 15, "HTTP timeout (seconds)")
	wafBypass := flag.Bool("waf-bypass", false, "Enable WAF bypass payload variants")
	htmlOut := flag.String("html-output", "", "Save HTML report")
	jsonOut := flag.String("json-output", "", "Save JSON report")
	csvOut := flag.String("csv-output", "", "Save CSV report")
	mdOut := flag.String("md-output", "", "Save Markdown report")
	output := flag.String("o", "", "Alias for --html-output")
	sqlOnly := flag.Bool("sql-only", false, "Test SQL injection only")
	xssOnly := flag.Bool("xss-only", false, "Test XSS only")
	cookie := flag.String("cookie", "", "Cookie value, e.g. session=abc123")
	var headerArgs core.HeaderList
	flag.Var(&headerArgs, "header", "Extra header (repeatable), e.g. 'Authorization: Bearer token'")
	flag.Var(&headerArgs, "H", "Same as --header (repeatable)")
	headersFile := flag.String("headers-file", "", "File with one 'Header: Value' per line")
	delay := flag.Int("delay", 0, "Delay ms between requests")
	userAgent := flag.String("user-agent", "Mozilla/5.0 sxel/"+version.Current, "Custom User-Agent")
	proxy := flag.String("proxy", "", "HTTP proxy, e.g. http://127.0.0.1:8080")
	verbose := flag.Bool("v", false, "Verbose output")
	ws := flag.Bool("ws", false, "Discover and test WebSocket endpoints")
	exclude := flag.String("exclude", "", "Skip URLs containing this substring")
	maxPages := flag.Int("max-pages", 0, "Max pages to crawl, 0 = unlimited")

	blind := flag.Bool("blind", false, "Enable blind SQLi (time-based + boolean-based)")
	headerScan := flag.Bool("header-scan", false, "Test HTTP headers as injection points")
	cookieScan := flag.Bool("cookie-scan", false, "Test cookies as injection points")
	sensitiveFiles := flag.Bool("sensitive-files", false, "Probe for exposed sensitive files/paths")
	openRedirect := flag.Bool("open-redirect", false, "Test for open redirect vulnerabilities")
	pathTraversal := flag.Bool("path-traversal", false, "Test for path/directory traversal")
	securityHdrs := flag.Bool("security-headers", false, "Audit security response headers")
	corsScan := flag.Bool("cors", false, "Test for CORS misconfiguration")
	httpMethods := flag.Bool("http-methods", false, "Check for dangerous HTTP methods")
	jsEndpoints := flag.Bool("js-endpoints", false, "Extract API endpoints from JS files")
	ssti := flag.Bool("ssti", false, "Test for Server-Side Template Injection")
	crlfScan := flag.Bool("crlf", false, "Test for CRLF / header injection")
	hostHeader := flag.Bool("host-header", false, "Test for Host header injection")
	jsonScan := flag.Bool("json-injection", false, "Test JSON body endpoints for SQLi/XSS")
	useRobots := flag.Bool("robots", false, "Parse robots.txt and sitemap.xml for extra targets")
	allFlag := flag.Bool("all", false, "Enable every scan module")

	cmdInjection := flag.Bool("cmdi", false, "Test for OS command injection")
	ssrfScan := flag.Bool("ssrf", false, "Test for Server-Side Request Forgery (SSRF)")
	xxeScan := flag.Bool("xxe", false, "Test for XML External Entity (XXE) injection")
	nosqlScan := flag.Bool("nosql", false, "Test for NoSQL (MongoDB) injection")
	rateLimit := flag.Int("rate-limit", 0, "Max requests per second globally (0 = unlimited)")

	dirScan := flag.Bool("dirscan", false, "Run directory / file brute force")
	wordlist := flag.String("wordlist", "", "Path to wordlist file for --dirscan")
	scopePatFlag := flag.String("scope", "", "Comma-separated scope patterns, e.g. '*.target.com,api.target.com'")
	outOfScope := flag.String("out-of-scope", "", "Comma-separated patterns to exclude from crawl, e.g. 'cdn.target.com'")
	wafDetect := flag.Bool("waf-detect", false, "Probe for WAF before scanning and auto-enable bypass if found")

	fileUpload := flag.Bool("file-upload", false, "Test for unrestricted file upload vulnerabilities")
	jwtScan := flag.Bool("jwt", false, "Test for JWT misconfiguration (alg:none, weak secret, alg confusion)")
	idorScan := flag.Bool("idor", false, "Test for IDOR — Insecure Direct Object Reference (numeric IDs)")
	graphqlScan := flag.Bool("graphql", false, "Probe GraphQL endpoints for introspection, batching, depth issues")

	resumeFlag := flag.Bool("resume", false, "Resume an interrupted scan from the last checkpoint file")
	checkpointFile := flag.String("checkpoint", core.DefaultCheckpointFile, "Checkpoint file path")

	csrfScan := flag.Bool("csrf", false, "Test for CSRF vulnerabilities in forms")
	cookieAuditFlag := flag.Bool("cookie-audit", false, "Audit cookie security flags (Secure, HttpOnly, SameSite)")
	subdomainEnumFlag := flag.Bool("subdomain-enum", false, "Enumerate subdomains via crt.sh and DNS brute-force")
	protoPollution := flag.Bool("proto-pollution", false, "Test for prototype pollution in JSON endpoints")
	deserializeFlag := flag.Bool("deserialize", false, "Test for insecure deserialization (PHP/Java/Python)")
	cachePoisonFlag := flag.Bool("cache-poison", false, "Test for web cache poisoning via unkeyed headers")
	lfiFlag := flag.Bool("lfi", false, "Test for LFI/RFI (PHP wrappers, remote include, log poisoning)")
	smugglingFlag := flag.Bool("smuggling", false, "Test for HTTP request smuggling (CL.TE/TE.CL)")
	rateLimitTestFlag := flag.Bool("rate-limit-test", false, "Test rate limiting defenses on target")
	subTakeoverFlag := flag.Bool("subdomain-takeover", false, "Check for subdomain takeover (CNAME dangling)")

	flag.Usage = func() {
		fmt.Println("Usage: sxel -u <URL> [OPTIONS]")
		fmt.Println()
		flag.PrintDefaults()
		fmt.Println(`
Examples:
  sxel -u "http://target.com/page?id=1"
  sxel -u "http://target.com" --crawl --depth 3 --waf-bypass
  sxel -u "http://target.com" --crawl --ws -o report.html
  sxel -u "http://target.com" --all --html-output report.html --json-output r.json
  sxel -u "http://target.com" --sql-only --blind --proxy http://127.0.0.1:8080
  sxel -l targets.txt --all --json-output results.json --list-concurrency 5
  sxel -u "http://target.com" -H "Authorization: Bearer xxx" -H "X-Api-Key: yyy"
  sxel -u "http://target.com" --jwt --cookie "session=abc; token=ey..."
  sxel -u "http://target.com" --graphql --idor --file-upload
  sxel -u "http://target.com" --all --checkpoint state.json
  sxel -u "http://target.com" --resume --checkpoint state.json`)
	}
	// ── Misc ─────────────────────────────────────────────────────────────────
	updateFlag := flag.Bool("update", false, "Update sxel to latest version")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *updateFlag {
		updater.Update()
		return
	}
	if *versionFlag {
		fmt.Println("sxel " + version.Current)
		return
	}

	banner.Print()

	target := *u
	if target == "" {
		target = *ulong
	}
	if target == "" && flag.NArg() > 0 {
		target = flag.Arg(0)
	}
	if *htmlOut == "" {
		*htmlOut = *output
	}

	listPath := *listFlag
	if listPath == "" {
		listPath = *listShort
	}

	var rawTargets []string
	if listPath != "" {
		urls, err := core.ReadURLList(listPath)
		if err != nil {
			fmt.Printf("[!] Failed to read --list file: %v\n", err)
			os.Exit(1)
		}
		if len(urls) == 0 {
			fmt.Println("[!] --list file contained no usable URLs")
			os.Exit(1)
		}
		rawTargets = urls
	} else if target != "" {
		rawTargets = []string{target}
	} else {
		flag.Usage()
		os.Exit(1)
	}

	for _, t := range rawTargets {
		p, err := url.Parse(t)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") {
			fmt.Printf("[!] Invalid URL - must start with http:// or https://: %s\n", t)
			os.Exit(1)
		}
		_ = p
	}

	headers, err := core.BuildHeaders(headerArgs, *headersFile)
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}

	if *allFlag {
		*blind = true
		*headerScan = true
		*cookieScan = true
		*sensitiveFiles = true
		*openRedirect = true
		*pathTraversal = true
		*securityHdrs = true
		*corsScan = true
		*httpMethods = true
		*jsEndpoints = true
		*ssti = true
		*crlfScan = true
		*hostHeader = true
		*jsonScan = true
		*wafBypass = true
		*useRobots = true
		*cmdInjection = true
		*ssrfScan = true
		*xxeScan = true
		*nosqlScan = true
		*dirScan = true
		*wafDetect = true
		*fileUpload = true
		*jwtScan = true
		*idorScan = true
		*graphqlScan = true
		*csrfScan = true
		*cookieAuditFlag = true
		*subdomainEnumFlag = true
		*protoPollution = true
		*deserializeFlag = true
		*cachePoisonFlag = true
		*lfiFlag = true
		*smugglingFlag = true
		*subTakeoverFlag = true
	}

	if *threads < 1 {
		*threads = 1
	}
	if *listConcurrency < 1 {
		*listConcurrency = 1
	}

	var scopePatterns, outOfScopePatterns []string
	if *scopePatFlag != "" {
		for _, p := range strings.Split(*scopePatFlag, ",") {
			if t := strings.TrimSpace(p); t != "" {
				scopePatterns = append(scopePatterns, t)
			}
		}
	}
	if *outOfScope != "" {
		for _, p := range strings.Split(*outOfScope, ",") {
			if t := strings.TrimSpace(p); t != "" {
				outOfScopePatterns = append(outOfScopePatterns, t)
			}
		}
	}
	if len(scopePatterns) > 0 || len(outOfScopePatterns) > 0 {
		var filtered []string
		for _, t := range rawTargets {
			parsed, err := url.Parse(t)
			if err != nil {
				fmt.Printf("[!] Skipping invalid URL: %s\n", t)
				continue
			}
			host := parsed.Host
			excluded := false
			for _, pat := range outOfScopePatterns {
				if engine.MatchScope(pat, host, t) {
					fmt.Printf("[!] Skipping out-of-scope: %s (matches %q)\n", t, pat)
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
			if len(scopePatterns) > 0 {
				matched := false
				for _, pat := range scopePatterns {
					if engine.MatchScope(pat, host, t) {
						matched = true
						break
					}
				}
				if !matched {
					fmt.Printf("[!] Skipping (not in scope): %s\n", t)
					continue
				}
			}
			filtered = append(filtered, t)
		}
		if len(filtered) == 0 {
			fmt.Println("[!] No targets remain after scope filtering")
			os.Exit(1)
		}
		fmt.Printf("[*] Scope filter: %d/%d target(s) in scope\n", len(filtered), len(rawTargets))
		rawTargets = filtered
	}

	cfg := &core.Config{
		URL:            target,
		Crawl:          *crawl,
		BasicCrawl:     *basicCrawl,
		Depth:          *depth,
		Threads:        *threads,
		Timeout:        *timeout,
		WAFBypass:      *wafBypass,
		HTMLOutput:     *htmlOut,
		JSONOutput:     *jsonOut,
		CSVOutput:      *csvOut,
		SQLOnly:        *sqlOnly,
		XSSOnly:        *xssOnly,
		Cookie:         *cookie,
		Headers:        headers,
		Delay:          *delay,
		UserAgent:      *userAgent,
		Proxy:          *proxy,
		Verbose:        *verbose,
		WS:             *ws,
		Exclude:        *exclude,
		MaxPages:       *maxPages,
		BlindSQLi:      *blind,
		HeaderScan:     *headerScan,
		CookieScan:     *cookieScan,
		SensitiveFiles: *sensitiveFiles,
		OpenRedirect:   *openRedirect,
		PathTraversal:  *pathTraversal,
		SecurityHdrs:   *securityHdrs,
		CORSScan:       *corsScan,
		HTTPMethods:    *httpMethods,
		JSEndpoints:    *jsEndpoints,
		SSTI:           *ssti,
		CRLFScan:       *crlfScan,
		HostHeader:     *hostHeader,
		JSONScan:       *jsonScan,
		AllChecks:      *allFlag,
		CmdInjection:   *cmdInjection,
		SSRFScan:       *ssrfScan,
		XXEScan:        *xxeScan,
		NoSQLScan:      *nosqlScan,
		RateLimit:      *rateLimit,
		DirScan:        *dirScan,
		Wordlist:       *wordlist,
		Scope:          scopePatterns,
		OutOfScope:     outOfScopePatterns,
		WAFAutoDetect:  *wafDetect,
		FileUpload:     *fileUpload,
		JWTScan:        *jwtScan,
		IDORScan:       *idorScan,
		GraphQL:        *graphqlScan,
		CheckpointFile: *checkpointFile,
		CSRF:           *csrfScan,
		CookieAudit:    *cookieAuditFlag,
		SubdomainEnum:  *subdomainEnumFlag,
		ProtoPollution: *protoPollution,
		Deserialize:    *deserializeFlag,
		CachePoison:    *cachePoisonFlag,
		LFI:            *lfiFlag,
		Smuggling:      *smugglingFlag,
		RateLimitTest:  *rateLimitTestFlag,
		SubTakeover:    *subTakeoverFlag,
	}

	if cfg.RateLimit > 0 {
		cfg.Limiter = core.NewRateLimiter(cfg.RateLimit)
		fmt.Printf("[*] Rate Limit  : %d req/sec\n", cfg.RateLimit)
	}

	var resumeResults []core.ScanResult
	if *resumeFlag {
		if cs, ok := core.LoadCheckpoint(*checkpointFile); ok {
			cfg.Checkpoint = cs
			resumeResults = make([]core.ScanResult, len(cs.Results))
			copy(resumeResults, cs.Results)
		} else {
			fmt.Println("[!] No checkpoint found — starting fresh scan")
			cfg.Checkpoint = core.NewCheckpoint(*checkpointFile)
		}
	} else {
		cfg.Checkpoint = core.NewCheckpoint(*checkpointFile)
	}

	start := time.Now()
	displayTarget := target
	if listPath != "" {
		displayTarget = fmt.Sprintf("%d targets from %s", len(rawTargets), listPath)
	}
	fmt.Printf("Target  : %s\n", displayTarget)
	fmt.Printf("Started : %s\n", start.Format("2006-01-02 15:04:05"))
	if len(headers) > 0 {
		fmt.Printf("[*] Extra Headers : %d\n", len(headers))
	}
	if cfg.WAFBypass {
		fmt.Println("[*] WAF Bypass : ENABLED")
	}
	if cfg.Crawl || cfg.BasicCrawl {
		mode := "deep"
		if cfg.BasicCrawl {
			mode = "basic"
		}
		fmt.Printf("[*] Crawl Mode : %s (max depth %d)\n", mode, cfg.Depth)
	}
	if cfg.WS {
		fmt.Println("[*] WebSocket  : scan enabled")
	}
	if cfg.BlindSQLi {
		fmt.Println("[*] Blind SQLi : enabled (slower due to time-based tests)")
	}

	client := core.NewHTTPClient(cfg)
	defer cfg.Limiter.Close()

	var allResults []core.ScanResult
	totalURLs := 0
	totalForms := 0

	if len(rawTargets) == 1 {
		fmt.Println("\n[*] Running site-wide checks...")
		res, urls, forms := scanTarget(client, cfg, rawTargets[0], *useRobots)
		allResults = res
		totalURLs = urls
		totalForms = forms
	} else {
		fmt.Printf("\n[*] Scanning %d targets from %s (concurrency %d)...\n", len(rawTargets), listPath, *listConcurrency)
		var wg sync.WaitGroup
		var mu sync.Mutex
		sem := make(chan struct{}, *listConcurrency)
		for _, t := range rawTargets {
			wg.Add(1)
			sem <- struct{}{}
			go func(tg string) {
				defer wg.Done()
				defer func() { <-sem }()
				res, urls, forms := scanTarget(client, cfg, tg, *useRobots)
				mu.Lock()
				allResults = append(allResults, res...)
				totalURLs += urls
				totalForms += forms
				mu.Unlock()
			}(t)
		}
		wg.Wait()
	}

	if *resumeFlag && len(resumeResults) > 0 {
		allResults = append(resumeResults, allResults...)
	}

	cfg.Checkpoint.Delete()

	allResults = dedupResults(allResults)

	elapsed := time.Since(start)
	fmt.Printf("\n[+] Scan complete in %v — %d URL(s), %d form(s), %d finding(s)\n",
		elapsed.Round(time.Millisecond), totalURLs, totalForms, len(allResults))

	if len(allResults) > 0 {
		fmt.Println("\n── Findings ───────────────────────────────────────────────")
		for _, r := range allResults {
			sevTag := severityTag(r.Severity)
			fmt.Printf("  %s [%s] %s %s\n", sevTag, r.Type, r.Method, r.URL)
			if r.Parameter != "" {
				fmt.Printf("    Parameter : %s\n", r.Parameter)
			}
			if r.Evidence != "" {
				fmt.Printf("    Evidence  : %s\n", r.Evidence)
			}
		}
		fmt.Println("────────────────────────────────────────────────────────────")
		writeReports(cfg, allResults)
		if *mdOut != "" {
			writeMDReport(*mdOut, allResults)
		}
	}
}

func scanTarget(client *http.Client, cfg *core.Config, target string, useRobots bool) ([]core.ScanResult, int, int) {
	var allResults []core.ScanResult
	var mu sync.Mutex

	var reqSent, reqFailed, reqTotalNS int64
	client = core.NewCountingClient(client, &reqSent, &reqFailed, &reqTotalNS)

	if cfg.WAFAutoDetect {
		wafResult := modules.AutoDetectWAF(client, cfg, target)
		if wafResult.Detected {
			fmt.Printf("[~] WAF detected: %s (%s)\n", wafResult.Vendor, wafResult.Evidence)
			cfg.WAFBypass = true
			fmt.Printf("[~] WAF Bypass: auto-enabled\n")
		} else {
			fmt.Printf("[+] WAF: not detected\n")
		}
	}

	if cfg.SecurityHdrs {
		allResults = append(allResults, modules.CheckSecurityHeaders(client, cfg, target)...)
	}
	if cfg.CORSScan {
		allResults = append(allResults, modules.CheckCORS(client, cfg, target)...)
	}
	if cfg.HTTPMethods {
		allResults = append(allResults, modules.CheckHTTPMethods(client, cfg, target)...)
	}
	if cfg.HostHeader {
		allResults = append(allResults, modules.ScanHostHeaderInjection(client, cfg, target)...)
	}
	if cfg.SensitiveFiles {
		allResults = append(allResults, engine.ScanSensitiveFiles(client, cfg, target)...)
	}

	var targets []core.CrawlResult
	var targetsMu sync.Mutex
	var seedURLs []string
	var totalForms int
	var totalURLs int

	crawlEnabled := cfg.Crawl || cfg.BasicCrawl
	depth := cfg.Depth
	if cfg.BasicCrawl {
		depth = 1
	}

	if crawlEnabled && useRobots {
		seedURLs = append(seedURLs, engine.ParseRobotsTxt(client, cfg, target)...)
		seedURLs = append(seedURLs, engine.ParseSitemap(client, cfg, target)...)
	}

	pageChan := make(chan core.CrawlResult, 200)
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)
	var doneCount int64
	progressDone := make(chan struct{})
	startTime := time.Now()

	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-tick.C:
				done := int(atomic.LoadInt64(&doneCount))
				sent := int(atomic.LoadInt64(&reqSent))
				failed := int(atomic.LoadInt64(&reqFailed))
				ns := atomic.LoadInt64(&reqTotalNS)
				lat := time.Duration(0)
				if sent > 0 {
					lat = time.Duration(ns / int64(sent))
				}
				fp := 0.0
				if sent > 0 {
					fp = float64(failed) / float64(sent) * 100
				}
				targetsMu.Lock()
				n := len(targets)
				targetsMu.Unlock()
				fmt.Printf("\r\033[K[*] scanned: %d, pending: %d, requestSent: %d, latency: %v, failedRatio: %.1f%%",
					done, n-done, sent, lat.Round(time.Millisecond), fp)
			}
		}
	}()

	scanPage := func(t core.CrawlResult) {
		wg.Add(1)
		go func() {
			sem <- struct{}{}
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { atomic.AddInt64(&doneCount, 1) }()

			if cfg.Checkpoint.IsScanned(t.URL) {
				if cfg.Verbose {
					fmt.Printf("\n    [skip] %s (already scanned)\n", t.URL)
				}
				return
			}
			if cfg.Delay > 0 {
				time.Sleep(time.Duration(cfg.Delay) * time.Millisecond)
			}
			var local []core.ScanResult
			runSQL := !cfg.XSSOnly || cfg.SQLOnly
			runXSS := !cfg.SQLOnly || cfg.XSSOnly
			if runSQL {
				local = append(local, modules.ScanSQLi(client, cfg, t)...)
				if cfg.BlindSQLi {
					local = append(local, modules.ScanBlindSQLiTime(client, cfg, t)...)
					local = append(local, modules.ScanBooleanBlindSQLi(client, cfg, t)...)
				}
			}
			if runXSS {
				local = append(local, modules.ScanXSS(client, cfg, t)...)
			}
			if cfg.WS {
				local = append(local, modules.ScanWebSocket(client, cfg, t.URL)...)
			}
			if cfg.OpenRedirect {
				local = append(local, modules.ScanOpenRedirect(client, cfg, t)...)
			}
			if cfg.PathTraversal {
				local = append(local, modules.ScanPathTraversal(client, cfg, t)...)
			}
			if cfg.SSTI {
				local = append(local, modules.ScanSSTI(client, cfg, t)...)
			}
			if cfg.CRLFScan {
				local = append(local, modules.ScanCRLFInjection(client, cfg, t)...)
			}
			if cfg.JSONScan {
				local = append(local, modules.ScanJSONInjection(client, cfg, t)...)
			}
			if cfg.CmdInjection {
				local = append(local, modules.ScanCmdInjection(client, cfg, t)...)
			}
			if cfg.SSRFScan {
				local = append(local, modules.ScanSSRF(client, cfg, t)...)
			}
			if cfg.XXEScan {
				local = append(local, modules.ScanXXE(client, cfg, t)...)
			}
			if cfg.NoSQLScan {
				local = append(local, modules.ScanNoSQLi(client, cfg, t)...)
			}
			if cfg.FileUpload {
				local = append(local, modules.ScanFileUpload(client, cfg, t)...)
			}
			if cfg.JWTScan {
				local = append(local, modules.ScanJWT(client, cfg, t)...)
			}
			if cfg.IDORScan {
				local = append(local, modules.ScanIDOR(client, cfg, t)...)
			}
			if cfg.CSRF {
				local = append(local, modules.ScanCSRF(cfg, t)...)
			}
			if cfg.ProtoPollution {
				local = append(local, modules.ScanProtoPollution(client, cfg, t)...)
			}
			if cfg.Deserialize {
				local = append(local, modules.ScanDeserialize(client, cfg, t)...)
			}
			if cfg.LFI {
				local = append(local, modules.ScanLFI(client, cfg, t)...)
			}
			if cfg.Smuggling {
				local = append(local, modules.ScanSmuggling(client, cfg, t)...)
			}
			if cfg.CachePoison {
				local = append(local, modules.ScanCachePoison(client, cfg, t)...)
			}
			cfg.Checkpoint.MarkScanned(t.URL, local)
			if len(local) > 0 {
				mu.Lock()
				allResults = append(allResults, local...)
				mu.Unlock()
			}
		}()
	}

	crawlDone := make(chan struct{})
	go func() {
		defer close(crawlDone)
		if crawlEnabled {
			cr := engine.NewCrawler(client, cfg)
			cr.OnPage = func(page core.CrawlResult, n int) {
				targetsMu.Lock()
				targets = append(targets, page)
				totalForms += len(page.Forms)
				targetsMu.Unlock()
				pageChan <- page
			}
			cr.Crawl(target, depth)
			seen := make(map[string]bool)
			targetsMu.Lock()
			for _, tr := range targets {
				seen[tr.URL] = true
			}
			targetsMu.Unlock()
			for _, su := range seedURLs {
				if !seen[su] {
					seen[su] = true
					fs, _ := engine.FetchForms(client, cfg, su)
					p := core.CrawlResult{URL: su, Forms: fs}
					targetsMu.Lock()
					targets = append(targets, p)
					totalForms += len(p.Forms)
					targetsMu.Unlock()
					pageChan <- p
				}
			}
		} else {
			fs, _ := engine.FetchForms(client, cfg, target)
			targets = []core.CrawlResult{{URL: target, Forms: fs}}
			totalForms = len(fs)
			for _, t := range targets {
				pageChan <- t
			}
			close(pageChan)
			return
		}
		if cfg.JSEndpoints {
			eps := engine.ExtractJSEndpoints(client, cfg, target)
			for _, ep := range eps {
				p := core.CrawlResult{URL: ep}
				targetsMu.Lock()
				targets = append(targets, p)
				targetsMu.Unlock()
				pageChan <- p
			}
		}
		close(pageChan)
	}()

	for t := range pageChan {
		scanPage(t)
	}
	<-crawlDone
	wg.Wait()
	close(progressDone)

	totalURLs = len(targets)
	fmt.Printf("\r\033[K[+] %d URL(s) scanned in %v\n", totalURLs, time.Since(startTime).Round(time.Millisecond))

	root := core.CrawlResult{URL: target}
	if cfg.HeaderScan {
		allResults = append(allResults, modules.ScanHeaderInjection(client, cfg, root)...)
	}
	if cfg.CookieScan {
		allResults = append(allResults, modules.ScanCookieInjection(client, cfg, root)...)
	}
	if cfg.DirScan {
		allResults = append(allResults, modules.ScanDirs(client, cfg, target)...)
	}
	if cfg.GraphQL {
		allResults = append(allResults, modules.ScanGraphQL(client, cfg, target)...)
	}
	if cfg.CookieAudit {
		allResults = append(allResults, modules.AuditCookies(client, cfg, target)...)
	}
	if cfg.SubdomainEnum {
		allResults = append(allResults, modules.EnumerateSubdomains(client, cfg, target)...)
	}
	if cfg.SubTakeover {
		allResults = append(allResults, modules.CheckSubdomainTakeover(client, cfg, target)...)
	}
	if cfg.RateLimitTest {
		fmt.Printf("[!] WARNING: --rate-limit-test sends 30 burst requests and may trigger WAF blacklists.\n")
		allResults = append(allResults, modules.TestRateLimiting(client, cfg, target)...)
	}

	return allResults, totalURLs, totalForms
}

func dedupResults(results []core.ScanResult) []core.ScanResult {
	seen := make(map[string]bool)
	var out []core.ScanResult
	for _, r := range results {
		key := r.Type + "|" + r.URL + "|" + r.Parameter + "|" + r.Payload
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

func severityTag(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "\033[1;35m[CRITICAL]\033[0m"
	case "HIGH":
		return "\033[31m[HIGH]\033[0m"
	case "MEDIUM":
		return "\033[33m[MEDIUM]\033[0m"
	case "LOW":
		return "\033[34m[LOW]\033[0m"
	default:
		return "\033[90m[INFO]\033[0m"
	}
}

func writeReports(cfg *core.Config, results []core.ScanResult) {
	if cfg.HTMLOutput != "" {
		writeHTMLReport(cfg.HTMLOutput, results)
	}
	if cfg.JSONOutput != "" {
		writeJSONReport(cfg.JSONOutput, results)
	}
	if cfg.CSVOutput != "" {
		writeCSVReport(cfg.CSVOutput, results)
	}
}

func writeHTMLReport(path string, results []core.ScanResult) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("[!] HTML report error: %v\n", err)
		return
	}
	defer f.Close()
	io.WriteString(f, `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>sxel Scan Report</title>
<style>body{font-family:monospace;background:#111;color:#0f0;padding:20px}h1{color:#0ff}
.finding{border-bottom:1px solid #333;padding:8px 0}.sev-CRITICAL{color:#f0f}.sev-HIGH{color:#f00}
.sev-MEDIUM{color:#ff0}.sev-LOW{color:#0af}.sev-INFO{color:#888}
table{width:100%;border-collapse:collapse}td{padding:4px 8px;vertical-align:top}
</style></head><body><h1>sxel Scan Report</h1><p>Findings: `+
		fmt.Sprintf("%d", len(results))+`</p><table>`)
	for _, r := range results {
		cls := "sev-" + r.Severity
		io.WriteString(f, fmt.Sprintf(
			`<tr class="finding"><td class="%s">[%s]</td><td>%s %s</td><td>%s</td></tr>`,
			cls, r.Severity, r.Method, escHTML(r.URL), escHTML(r.Evidence)))
	}
	io.WriteString(f, "</table></body></html>")
	fmt.Printf("[+] HTML report -> %s\n", path)
}

func writeJSONReport(path string, results []core.ScanResult) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("[!] JSON report error: %v\n", err)
		return
	}
	defer f.Close()
	io.WriteString(f, "[\n")
	for i, r := range results {
		comma := ""
		if i < len(results)-1 {
			comma = ","
		}
		io.WriteString(f, fmt.Sprintf(
			`  {"type":%q,"url":%q,"method":%q,"parameter":%q,"payload":%q,"severity":%q,"evidence":%q,"timestamp":%q}%s`+"\n",
			r.Type, r.URL, r.Method, r.Parameter, r.Payload, r.Severity, r.Evidence,
			r.Timestamp.Format(time.RFC3339), comma))
	}
	io.WriteString(f, "]\n")
	fmt.Printf("[+] JSON report -> %s\n", path)
}

func writeCSVReport(path string, results []core.ScanResult) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("[!] CSV report error: %v\n", err)
		return
	}
	defer f.Close()
	io.WriteString(f, "Type,URL,Method,Parameter,Payload,Severity,Evidence,Timestamp\n")
	for _, r := range results {
		io.WriteString(f, fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(r.Type), csvEscape(r.URL), csvEscape(r.Method),
			csvEscape(r.Parameter), csvEscape(r.Payload), csvEscape(r.Severity),
			csvEscape(r.Evidence), csvEscape(r.Timestamp.Format(time.RFC3339))))
	}
	fmt.Printf("[+] CSV report -> %s\n", path)
}

func writeMDReport(path string, results []core.ScanResult) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("[!] Markdown report error: %v\n", err)
		return
	}
	defer f.Close()
	io.WriteString(f, "# sxel Scan Report\n\n")
	io.WriteString(f, fmt.Sprintf("**Findings:** %d\n\n", len(results)))
	io.WriteString(f, "| Severity | Type | URL | Method | Parameter | Evidence |\n")
	io.WriteString(f, "|---|---|---|---|---|---|\n")
	for _, r := range results {
		io.WriteString(f, fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			r.Severity, r.Type, r.URL, r.Method, r.Parameter, r.Evidence))
	}
	fmt.Printf("[+] Markdown report -> %s\n", path)
}

func escHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
