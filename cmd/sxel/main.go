package main

import (
	"encoding/json"
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
	"github.com/SentinelXofficial/sxel/internal/output"
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
	outFlag := flag.String("o", "", "Alias for --html-output")
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

	// Template engine
	templatesFlag := flag.Bool("templates", false, "Run YAML-based template scans")
	templateDir := flag.String("template-dir", "./templates/", "Path to templates directory")

	// Sprint B flags
	clutchFlag := flag.Bool("clutch", false, "Detect race condition / TOCTOU vulnerabilities")
	snipeFlag := flag.Bool("snipe", false, "All modules attack single endpoint simultaneously (deep-dive)")
	strobeFlag := flag.Bool("strobe", false, "Full adaptive deep-dive pipeline (fingerprint → smart scan → chains → templates)")
	breachFlag := flag.Bool("breach", false, "Probe OAuth + SAML misconfigurations")
	grpcFlag := flag.Bool("grpc", false, "Probe gRPC reflection + REST gateway")

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
	updateTemplatesFlag := flag.Bool("update-templates", false, "Update templates to latest version")
	convertNucleiFlag := flag.String("convert-nuclei", "", "Convert Nuclei templates from given directory to sxel format")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *updateFlag {
		updater.Update()
		return
	}
	if *updateTemplatesFlag {
		updater.UpdateTemplates(*templateDir)
		return
	}
	if *convertNucleiFlag != "" {
		output.Info("Converting Nuclei templates from %s → %s ...", *convertNucleiFlag, *templateDir)
		updater.ConvertNucleiTemplates(*convertNucleiFlag, *templateDir)
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
		*htmlOut = *outFlag
	}

	listPath := *listFlag
	if listPath == "" {
		listPath = *listShort
	}

	var rawTargets []string
	if listPath != "" {
		urls, err := core.ReadURLList(listPath)
		if err != nil {
			output.Error("Failed to read --list file: %v", err)
			os.Exit(1)
		}
		if len(urls) == 0 {
			output.Error("--list file contained no usable URLs")
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
			output.Error("Invalid URL - must start with http:// or https://: %s", t)
			os.Exit(1)
		}
		_ = p
	}

	headers, err := core.BuildHeaders(headerArgs, *headersFile)
	if err != nil {
		output.Error("%v", err)
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
		*templatesFlag = true
		*clutchFlag = true
		*snipeFlag = true
		*strobeFlag = true
		*breachFlag = true
		*grpcFlag = true
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
				output.Error("Skipping invalid URL: %s", t)
				continue
			}
			host := parsed.Host
			excluded := false
			for _, pat := range outOfScopePatterns {
				if engine.MatchScope(pat, host, t) {
					output.Warn("Skipping out-of-scope: %s (matches %q)", t, pat)
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
					output.Warn("Skipping (not in scope): %s", t)
					continue
				}
			}
			filtered = append(filtered, t)
		}
		if len(filtered) == 0 {
			output.Error("No targets remain after scope filtering")
			os.Exit(1)
		}
		output.Info("Scope filter: %d/%d target(s) in scope", len(filtered), len(rawTargets))
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
		Templates:      *templatesFlag,
		TemplateDir:    *templateDir,
		Clutch:         *clutchFlag,
		Snipe:          *snipeFlag,
		Strobe:         *strobeFlag,
		Breach:         *breachFlag,
		Grpc:           *grpcFlag,
	}

	if cfg.RateLimit > 0 {
		cfg.Limiter = core.NewRateLimiter(cfg.RateLimit)
		output.Info("Rate Limit: %d req/sec", cfg.RateLimit)
	}

	var resumeResults []core.ScanResult
	if *resumeFlag {
		if cs, ok := core.LoadCheckpoint(*checkpointFile); ok {
			cfg.Checkpoint = cs
			resumeResults = make([]core.ScanResult, len(cs.Results))
			copy(resumeResults, cs.Results)
		} else {
			output.Warn("No checkpoint found — starting fresh scan")
			cfg.Checkpoint = core.NewCheckpoint(*checkpointFile)
		}
	} else {
		cfg.Checkpoint = core.NewCheckpoint(*checkpointFile)
	}

	start := time.Now()

	// ── Module loading summary ───────────────────────────────────────────────
	printModuleSummary(cfg)

	displayTarget := target
	if listPath != "" {
		displayTarget = fmt.Sprintf("%d targets from %s", len(rawTargets), listPath)
	}
	output.Info("Target: %s", displayTarget)
	if len(headers) > 0 {
		output.Info("Extra Headers: %d", len(headers))
	}
	if cfg.WAFBypass {
		output.Info("WAF Bypass: ENABLED")
	}
	if cfg.Crawl || cfg.BasicCrawl {
		mode := "deep"
		if cfg.BasicCrawl {
			mode = "basic"
		}
		output.Info("Crawl Mode: %s (max depth %d)", mode, cfg.Depth)
	}
	if cfg.WS {
		output.Info("WebSocket: scan enabled")
	}
	if cfg.BlindSQLi {
		output.Info("Blind SQLi: enabled (slower due to time-based tests)")
	}

	// ── Load YAML templates ──────────────────────────────────────────────────
	var loadedTemplates []engine.Template
	var templatesVersion string
	if cfg.Templates {
		// Auto-download on first run if no templates exist yet
		updater.EnsureTemplates(cfg.TemplateDir)

		var loadErr error
		loadedTemplates, loadErr = engine.LoadTemplates(cfg.TemplateDir)
		if loadErr != nil {
			output.Warn("Cannot load templates from %q: %v — continuing without templates", cfg.TemplateDir, loadErr)
		} else if len(loadedTemplates) > 0 {
			templatesVersion = engine.LoadTemplateVersion(cfg.TemplateDir)
			verStr := ""
			if templatesVersion != "" {
				verStr = fmt.Sprintf(" (%s)", templatesVersion)
			}
			output.Info("Loaded %d template(s) from %s%s", len(loadedTemplates), cfg.TemplateDir, verStr)
		}

		// Non-blocking check for template updates (fire-and-forget)
		if templatesVersion != "" {
			go func(localVer string) {
				latest := updater.FetchLatestTemplatesVersion()
				if latest != "" && latest != localVer {
					output.Warn("Templates %s available (you have %s) — run: sxel --update-templates", latest, localVer)
				}
			}(templatesVersion)
		}
	}

	// ── Start OOB callback server (for blind SSRF/XXE/CMDI detection) ─────────
	var oobServer *engine.OOBServer
	if cfg.AllChecks || cfg.SSRFScan || cfg.XXEScan || cfg.CmdInjection {
		var oobErr error
		oobServer, oobErr = engine.NewOOBServer()
		if oobErr != nil {
			output.Warn("Cannot start OOB callback server: %v", oobErr)
		} else {
			defer oobServer.Close()
			cfg.OOBAddress = oobServer.Address
		}
	}

	client := core.NewHTTPClient(cfg)
	if cfg.Limiter != nil {
		defer cfg.Limiter.Close()
	}

	var allResults []core.ScanResult
	totalURLs := 0
	totalForms := 0

	if len(rawTargets) == 1 {
		fmt.Println()
		output.Info("Running site-wide checks...")
		res, urls, forms := scanTarget(client, cfg, rawTargets[0], *useRobots, loadedTemplates, oobServer)
		allResults = res
		totalURLs = urls
		totalForms = forms
	} else {
		fmt.Println()
		output.Info("Scanning %d targets from %s (concurrency %d)...", len(rawTargets), listPath, *listConcurrency)
		var wg sync.WaitGroup
		var mu sync.Mutex
		sem := make(chan struct{}, *listConcurrency)
		for _, t := range rawTargets {
			wg.Add(1)
			sem <- struct{}{}
			go func(tg string) {
				defer wg.Done()
				defer func() { <-sem }()
				cfgCopy := *cfg
				res, urls, forms := scanTarget(client, &cfgCopy, tg, *useRobots, loadedTemplates, oobServer)
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
	fmt.Println()
	output.Success("Scan complete in %v — %d URL(s), %d form(s), %d finding(s)",
		elapsed.Round(time.Millisecond), totalURLs, totalForms, len(allResults))

	if len(allResults) > 0 {
		writeReports(cfg, allResults)
		if *mdOut != "" {
			writeMDReport(*mdOut, allResults)
		}
	}
}

// printModuleSummary lists which scan modules are enabled, Xray-style.
func printModuleSummary(cfg *core.Config) {
	var mods []string
	add := func(name string, enabled bool) {
		if enabled {
			mods = append(mods, name)
		}
	}
	add("SQLi", !cfg.XSSOnly || cfg.SQLOnly)
	add("BlindSQLi", cfg.BlindSQLi)
	add("XSS", !cfg.SQLOnly || cfg.XSSOnly)
	add("SSRF", cfg.SSRFScan)
	add("CMDI", cfg.CmdInjection)
	add("LFI/RFI", cfg.LFI)
	add("NoSQLi", cfg.NoSQLScan)
	add("XXE", cfg.XXEScan)
	add("SSTI", cfg.SSTI)
	add("CRLF", cfg.CRLFScan)
	add("OpenRedirect", cfg.OpenRedirect)
	add("PathTraversal", cfg.PathTraversal)
	add("HeaderInjection", cfg.HeaderScan)
	add("CookieInjection", cfg.CookieScan)
	add("HostHeader", cfg.HostHeader)
	add("JSONInjection", cfg.JSONScan)
	add("DirScan", cfg.DirScan)
	add("SensitiveFiles", cfg.SensitiveFiles)
	add("SecurityHeaders", cfg.SecurityHdrs)
	add("CORS", cfg.CORSScan)
	add("HTTPMethods", cfg.HTTPMethods)
	add("JSEndpoints", cfg.JSEndpoints)
	add("WAFDetect", cfg.WAFAutoDetect)
	add("FileUpload", cfg.FileUpload)
	add("JWT", cfg.JWTScan)
	add("IDOR", cfg.IDORScan)
	add("GraphQL", cfg.GraphQL)
	add("CSRF", cfg.CSRF)
	add("CookieAudit", cfg.CookieAudit)
	add("SubdomainEnum", cfg.SubdomainEnum)
	add("ProtoPollution", cfg.ProtoPollution)
	add("Deserialize", cfg.Deserialize)
	add("CachePoison", cfg.CachePoison)
	add("Smuggling", cfg.Smuggling)
	add("RateLimitTest", cfg.RateLimitTest)
	add("SubTakeover", cfg.SubTakeover)
	add("WebSocket", cfg.WS)
	add("WAFBypass", cfg.WAFBypass)
	add("Clutch", cfg.Clutch)
	add("Snipe", cfg.Snipe)
	add("Strobe", cfg.Strobe)
	add("Breach", cfg.Breach)
	add("Grpc", cfg.Grpc)
	add("Templates", cfg.Templates)

	output.Info("Loaded %d scan module(s)", len(mods))
	if len(mods) > 0 {
		output.Info("Enabled: %s", strings.Join(mods, ", "))
	}
}

func scanTarget(client *http.Client, cfg *core.Config, target string, useRobots bool, templates []engine.Template, oobServer *engine.OOBServer) ([]core.ScanResult, int, int) {
	var allResults []core.ScanResult
	var mu sync.Mutex

	var reqSent, reqFailed, reqTotalNS int64
	client = core.NewCountingClient(client, &reqSent, &reqFailed, &reqTotalNS)

	if cfg.WAFAutoDetect {
		wafResult := modules.AutoDetectWAF(client, cfg, target)
		if wafResult.Detected {
			output.Warn("WAF detected: %s (%s)", wafResult.Vendor, wafResult.Evidence)
			cfg.WAFBypass = true
			output.Warn("WAF Bypass: auto-enabled")
		} else {
			output.Success("WAF: not detected")
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
	threads := cfg.Threads
	if threads < 1 {
		threads = 1
	}
	sem := make(chan struct{}, threads)
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
				sent := atomic.LoadInt64(&reqSent)
				failed := atomic.LoadInt64(&reqFailed)
				ns := atomic.LoadInt64(&reqTotalNS)
				lat := time.Duration(0)
				if sent > 0 {
					lat = time.Duration(ns / sent)
				}
				fp := 0.0
				if sent > 0 {
					fp = float64(failed) / float64(sent) * 100
				}
				targetsMu.Lock()
				n := len(targets)
				targetsMu.Unlock()
				output.Progress(done, n-done, sent, lat, fp)
			}
		}
	}()

	scanPage := func(t core.CrawlResult) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { atomic.AddInt64(&doneCount, 1) }()

			if cfg.Checkpoint.IsScanned(t.URL) {
				if cfg.Verbose {
					output.Verbose("[skip] %s (already scanned)", t.URL)
				}
				return
			}
			// Apply delay BEFORE acquiring the semaphore so other workers
			// can use the slot while this one waits.
			if cfg.Delay > 0 {
				time.Sleep(time.Duration(cfg.Delay) * time.Millisecond)
			}

			sem <- struct{}{}
			defer func() { <-sem }()
			var local []core.ScanResult

			// Strobe mode: adaptive deep-dive with fingerprinting + smart module selection
			if cfg.Strobe {
				local = modules.ScanStrobe(client, cfg, t, templates)
				cfg.Checkpoint.MarkScanned(t.URL, local)
				if len(local) > 0 {
					fmt.Printf("\r\033[K")
					for _, r := range local {
						output.PrintFinding(output.Finding{
							Type: r.Type, URL: r.URL, Method: r.Method,
							Parameter: r.Parameter, Payload: r.Payload,
							Severity: r.Severity, Evidence: r.Evidence,
							Timestamp:  r.Timestamp.Format("2006-01-02 15:04:05"),
							ParamKey:   r.ParamKey, ParamValue: r.ParamValue,
							Position:   r.Position, Extra: r.Extra,
						})
					}
					mu.Lock()
					allResults = append(allResults, local...)
					mu.Unlock()
				}
				return
			}

			// Snipe mode: deep-dive all modules on single endpoint
			if cfg.Snipe {
				local = runSnipe(client, cfg, t.URL, templates)
				cfg.Checkpoint.MarkScanned(t.URL, local)
				if len(local) > 0 {
					fmt.Printf("\r\033[K")
					for _, r := range local {
						output.PrintFinding(output.Finding{
							Type: r.Type, URL: r.URL, Method: r.Method,
							Parameter: r.Parameter, Payload: r.Payload,
							Severity: r.Severity, Evidence: r.Evidence,
							Timestamp:  r.Timestamp.Format("2006-01-02 15:04:05"),
							ParamKey:   r.ParamKey, ParamValue: r.ParamValue,
							Position:   r.Position, Extra: r.Extra,
						})
					}
					mu.Lock()
					allResults = append(allResults, local...)
					mu.Unlock()
				}
				return
			}

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
			// Run OOB probes for blind SSRF/XXE/CMDI detection
			if oobServer != nil {
				local = append(local, engine.RunOOBProbes(client, cfg, t.URL, oobServer)...)
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
			if cfg.Clutch {
				local = append(local, modules.ScanClutch(client, cfg, t)...)
			}
			if cfg.Breach {
				local = append(local, modules.ScanBreach(client, cfg, t)...)
			}
			if cfg.Grpc {
				local = append(local, modules.ScanGrpc(client, cfg, t)...)
			}
			if cfg.Templates && len(templates) > 0 {
				local = append(local, engine.RunTemplates(client, cfg, t.URL, templates)...)
			}
			cfg.Checkpoint.MarkScanned(t.URL, local)
			if len(local) > 0 {
				// Clear progress line, print findings Xray-style, then add to results
				fmt.Printf("\r\033[K")
				for _, r := range local {
					output.PrintFinding(output.Finding{
						Type: r.Type, URL: r.URL, Method: r.Method,
						Parameter: r.Parameter, Payload: r.Payload,
						Severity: r.Severity, Evidence: r.Evidence,
						Timestamp:  r.Timestamp.Format("2006-01-02 15:04:05"),
						ParamKey:   r.ParamKey, ParamValue: r.ParamValue,
						Position:   r.Position, Extra: r.Extra,
					})
				}
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
	fmt.Printf("\r\033[K")
	output.Success("%d URL(s) scanned in %v", totalURLs, time.Since(startTime).Round(time.Millisecond))

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
		output.Warn("--rate-limit-test sends 30 burst requests and may trigger WAF blacklists.")
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
		output.Error("HTML report: %v", err)
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
	output.Success("HTML report -> %s", path)
}

func writeJSONReport(path string, results []core.ScanResult) {
	f, err := os.Create(path)
	if err != nil {
		output.Error("JSON report: %v", err)
		return
	}
	defer f.Close()
	type entry struct {
		Type      string `json:"type"`
		URL       string `json:"url"`
		Method    string `json:"method"`
		Parameter string `json:"parameter"`
		Payload   string `json:"payload"`
		Severity  string `json:"severity"`
		Evidence  string `json:"evidence"`
		Timestamp string `json:"timestamp"`
	}
	entries := make([]entry, len(results))
	for i, r := range results {
		entries[i] = entry{
			Type: r.Type, URL: r.URL, Method: r.Method,
			Parameter: r.Parameter, Payload: r.Payload,
			Severity: r.Severity, Evidence: r.Evidence,
			Timestamp: r.Timestamp.Format(time.RFC3339),
		}
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		output.Error("JSON report encode: %v", err)
		return
	}
	output.Success("JSON report -> %s", path)
}

func writeCSVReport(path string, results []core.ScanResult) {
	f, err := os.Create(path)
	if err != nil {
		output.Error("CSV report: %v", err)
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
	output.Success("CSV report -> %s", path)
}

func writeMDReport(path string, results []core.ScanResult) {
	f, err := os.Create(path)
	if err != nil {
		output.Error("Markdown report: %v", err)
		return
	}
	defer f.Close()
	io.WriteString(f, "# sxel Scan Report\n\n")
	io.WriteString(f, fmt.Sprintf("**Findings:** %d\n\n", len(results)))
	io.WriteString(f, "| Severity | Type | URL | Method | Parameter | Evidence |\n")
	io.WriteString(f, "|---|---|---|---|---|---|\n")
	for _, r := range results {
		io.WriteString(f, fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			mdEscape(r.Severity), mdEscape(r.Type), mdEscape(r.URL),
			mdEscape(r.Method), mdEscape(r.Parameter), mdEscape(r.Evidence)))
	}
	output.Success("Markdown report -> %s", path)
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func escHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// runSnipe executes ALL scan modules against a single endpoint (deep-dive mode).
func runSnipe(client *http.Client, cfg *core.Config, targetURL string, templates []engine.Template) []core.ScanResult {
	target := core.CrawlResult{URL: targetURL}
	var allResults []core.ScanResult
	var mu sync.Mutex

	output.Info("Snipe mode: deep-dive scanning %s", targetURL)

	type snipeMod struct {
		name string
		fn   func(*http.Client, *core.Config, core.CrawlResult) []core.ScanResult
	}

	// Phase 1: Fast (analysis only)
	fast := []snipeMod{
		{"SecurityHeaders", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.CheckSecurityHeaders(c, cf, targetURL)
		}},
		{"CORS", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.CheckCORS(c, cf, targetURL)
		}},
		{"DirScan", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.ScanDirs(c, cf, targetURL)
		}},
		{"GraphQL", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.ScanGraphQL(c, cf, targetURL)
		}},
		{"CookieAudit", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.AuditCookies(c, cf, targetURL)
		}},
		{"SubdomainEnum", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.EnumerateSubdomains(c, cf, targetURL)
		}},
		{"SubTakeover", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.CheckSubdomainTakeover(c, cf, targetURL)
		}},
	}

	// Phase 2: Active injection
	med := []snipeMod{
		{"SQLi", modules.ScanSQLi},
		{"XSS", modules.ScanXSS},
		{"SSRF", modules.ScanSSRF},
		{"CMDI", modules.ScanCmdInjection},
		{"LFI", modules.ScanLFI},
		{"XXE", modules.ScanXXE},
		{"NoSQLi", modules.ScanNoSQLi},
		{"SSTI", modules.ScanSSTI},
		{"JWT", modules.ScanJWT},
		{"IDOR", modules.ScanIDOR},
		{"CSRF", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult { return modules.ScanCSRF(cf, t) }},
		{"FileUpload", modules.ScanFileUpload},
		{"Deserialize", modules.ScanDeserialize},
		{"ProtoPollution", modules.ScanProtoPollution},
		{"CachePoison", modules.ScanCachePoison},
		{"Smuggling", modules.ScanSmuggling},
		{"Clutch", modules.ScanClutch},
	}

	// Phase 3: Heavy (blind/timing)
	heavy := []snipeMod{
		{"BlindSQLi", modules.ScanBlindSQLiTime},
		{"BooleanSQLi", modules.ScanBooleanBlindSQLi},
	}

	phases := [][]snipeMod{fast, med, heavy}
	labels := []string{"fast", "medium", "heavy"}

	for pi, mods := range phases {
		output.Info("Snipe %s: %d module(s)", labels[pi], len(mods))
		var wg sync.WaitGroup
		for _, m := range mods {
			wg.Add(1)
			go func(mod snipeMod) {
				defer wg.Done()
				res := mod.fn(client, cfg, target)
				if len(res) > 0 {
					mu.Lock()
					allResults = append(allResults, res...)
					mu.Unlock()
				}
			}(m)
		}
		wg.Wait()
	}

	// Templates
	if len(templates) > 0 {
		allResults = append(allResults, engine.RunTemplates(client, cfg, targetURL, templates)...)
	}

	return allResults
}

func csvEscape(s string) string {
	// Prevent CSV/Formula injection: prefix with single quote if the field
	// starts with a character that spreadsheet apps interpret as a formula.
	if len(s) > 0 && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@') {
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
