package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SentinelXofficial/sxel/internal/banner"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/internal/updater"
	"github.com/SentinelXofficial/sxel/internal/version"
	"github.com/SentinelXofficial/sxel/pkg/config"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/engine"
	"github.com/SentinelXofficial/sxel/pkg/modules"
	"github.com/SentinelXofficial/sxel/pkg/poc"
	"github.com/SentinelXofficial/sxel/pkg/report"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/sync/errgroup"
)

func applyModules(sel string, setters map[string]func()) error {
	var names []string
	for _, name := range strings.Split(sel, ",") {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return fmt.Errorf("empty --modules list")
	}
	if names[0] == "help" {
		printModulesHelp(setters)
		os.Exit(0)
	}
	for _, name := range names {
		fn, ok := setters[name]
		if !ok {
			return fmt.Errorf("unknown module %q (see --modules help for the valid module list)", name)
		}
		fn()
	}
	return nil
}

func printModulesHelp(setters map[string]func()) {
	fmt.Println("Valid --modules values (comma-separated):")
	var sorted []string
	for name := range setters {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		fmt.Printf("  %s\n", name)
	}
	fmt.Println("\nExample: --modules sqli,xss,webshell  (only these run)")
}

func randomUA() string {
	ua := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36",
	}
	return ua[time.Now().UnixNano()%int64(len(ua))]
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "proxy" {
		runProxy(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "recon" {
		runRecon(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "poclint" {
		runPocLint(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "servicescan" {
		runServiceScan(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "reverse" {
		runReverse(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "burp-gamma" {
		runBurpGamma(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "transform" {
		runTransform(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "genca" {
		runGenCA(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "plugin" {
		runPlugin(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "httpfuzzer" {
		runHTTPFuzzer(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "http" {
		runHTTP(os.Args[2:])
		return
	}
	u := flag.String("u", "", "Target URL, e.g. http://site.com/page?id=1")
	ulong := flag.String("url", "", "Same as -u")
	listFlag := flag.String("list", "", "File with target URLs, one per line")
	listShort := flag.String("l", "", "Same as --list")
	listConcurrency := flag.Int("list-concurrency", 3, "Targets to scan concurrently when using --list")
	crawl := flag.Bool("crawl", false, "Deep recursive crawl")
	basicCrawl := flag.Bool("basic-crawl", false, "Shallow crawl (homepage only, no link following)")
	jsCrawl := flag.Bool("js-crawl", false, "Render pages with headless Chrome (auto-downloads headless-shell on first use) to discover JS-generated links and forms")
	threads := flag.Int("threads", 5, "Concurrent scan threads")
	timeout := flag.Int("timeout", 30, "HTTP timeout (seconds)")
	wafBypass := flag.Bool("waf-bypass", false, "Enable WAF bypass payload variants")
	htmlOut := flag.String("html-output", "", "Save HTML report")
	jsonOut := flag.String("json-output", "", "Save JSON report")
	csvOut := flag.String("csv-output", "", "Save CSV report")
	mdOut := flag.String("md-output", "", "Save Markdown report")
	evidenceDir := flag.String("evidence-dir", "", "Dump per-finding request/response files into this directory")
	outFlag := flag.String("o", "", "Alias for --html-output")
	sqliFlag := flag.Bool("sqli", false, "Enable SQL injection scan (default: on unless other module flags are given)")
	xssFlag := flag.Bool("xss", false, "Enable XSS scan (default: on unless other module flags are given)")
	cookie := flag.String("cookie", "", "Cookie value, e.g. session=abc123")
	var headerArgs core.HeaderList
	flag.Var(&headerArgs, "header", "Extra header (repeatable), e.g. 'Authorization: Bearer token'")
	flag.Var(&headerArgs, "H", "Same as --header (repeatable)")
	headersFile := flag.String("headers-file", "", "File with one 'Header: Value' per line")
	delay := flag.Int("delay", 0, "Delay ms between requests")
	userAgent := flag.String("user-agent", randomUA(), "Custom User-Agent")
	proxy := flag.String("proxy", "", "HTTP proxy, e.g. http://127.0.0.1:8080")
	verbose := flag.Bool("v", false, "Verbose output")
	clientCert := flag.String("client-cert", "", "mTLS client certificate file (PEM)")
	clientKey := flag.String("client-key", "", "mTLS client private key file (PEM)")
	ws := flag.Bool("ws", false, "Discover and test WebSocket endpoints")
	exclude := flag.String("exclude", "", "Skip URLs containing this substring")
	maxPages := flag.Int("max-pages", 0, "Max pages to crawl, 0 = unlimited")

	blind := flag.Bool("blind", true, "Blind SQLi (time-based + boolean-based); disable with --blind=false")
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
	modulesFlag := flag.String("modules", "", "Modules to run, comma-separated, e.g. 'sqli,xss,webshell'. If set, only these run. All: 'all'. Valid: sqli,xss,blind,header-scan,cookie-scan,sensitive-files,open-redirect,path-traversal,security-headers,cors,http-methods,js-endpoints,ssti,crlf,host-header,json-injection,cmdi,ssrf,xxe,nosql,dirscan,file-upload,jwt,webshell,shell,idor,graphql,csrf,cookie-audit,proto-pollution,deserialize,cache-poison,cache-deception,smuggling,hpp,dom-audit,lfi,ldap-xpath,h2c,jarm,dom,mass-assign,axfr,subdomain-enum,subdomain-takeover,templates,ws,waf-detect,rate-limit-test,clutch,api-security,snipe,strobe,breach,grpc")

	cmdInjection := flag.Bool("cmdi", false, "Test for OS command injection")
	ssrfScan := flag.Bool("ssrf", false, "Test for Server-Side Request Forgery (SSRF)")
	xxeScan := flag.Bool("xxe", false, "Test for XML External Entity (XXE) injection")
	nosqlScan := flag.Bool("nosql", false, "Test for NoSQL (MongoDB) injection")
	rateLimit := flag.Int("rate-limit", 0, "Max requests per second globally (0 = unlimited)")

	dirScan := flag.Bool("dirscan", false, "Run directory / file brute force")
	wordlist := flag.String("wordlist", "", "Path to wordlist file for --dirscan")
	dirExt := flag.String("dir-ext", "", "Extension stacking for --dirscan, e.g. '.php,.bak,.swp'")
	dirDepth := flag.Int("dir-depth", 0, "Recursive depth for --dirscan when directories are found (0 = off)")
	dirContent := flag.Bool("dir-content-check", false, "Fetch sensitive files found by --dirscan and scan for secrets")
	scopePatFlag := flag.String("scope", "", "Crawl scope: default same-site + subdomains; '*.target.com' wildcard or full URL prefix to override")
	outOfScope := flag.String("out-of-scope", "", "Comma-separated patterns to exclude from crawl, e.g. 'cdn.target.com'")
	wafDetect := flag.Bool("waf-detect", true, "Probe for WAF before scanning and ask to enable bypass if found (set false to disable)")

	fileUpload := flag.Bool("file-upload", false, "Test for unrestricted file upload vulnerabilities")
	jwtScan := flag.Bool("jwt", false, "Test for JWT misconfiguration (alg:none, weak secret, alg confusion)")
	webShellScan := flag.Bool("webshell", false, "Detect exposed webshells (c99/r57/b374k/wso/alfashell + obfuscated eval shells)")
	shellScan := flag.Bool("shell", false, "Same as --webshell")
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
	hppFlag := flag.Bool("hpp", false, "Test for HTTP Parameter Pollution (duplicate params)")
	domAuditFlag := flag.Bool("dom-audit", false, "Static DOM-XSS audit of inline/external scripts")
	ldxFlag := flag.Bool("ldap-xpath", false, "Test LDAP and XPath filter injection")
	h2cFlag := flag.Bool("h2c", false, "Check for cleartext HTTP/2 (h2c upgrade)")
	jarmFlag := flag.Bool("jarm", false, "Fingerprint TLS stack via JARM handshake")
	domFlag := flag.Bool("dom", false, "Verify XSS payloads in a real headless browser (DOM context)")
	massFlag := flag.Bool("mass-assign", false, "Probe JSON APIs for mass assignment (unexpected field acceptance)")
	axfrFlag := flag.Bool("axfr", false, "Check for open DNS zone transfers (AXFR) on the target's nameservers")
	smugglingFlag := flag.Bool("smuggling", false, "Test for HTTP request smuggling (CL.TE/TE.CL)")
	cacheDeceptionFlag := flag.Bool("cache-deception", false, "Test for web cache deception via static-extension path tricks")
	rateLimitTestFlag := flag.Bool("rate-limit-test", false, "Test rate limiting defenses on target")
	subTakeoverFlag := flag.Bool("subdomain-takeover", false, "Check for subdomain takeover (CNAME dangling)")

	templatesFlag := flag.Bool("templates", false, "Run YAML-based template scans")
	templateDir := flag.String("template-dir", "./templates/", "Path to templates directory")
	templateSeverity := flag.String("template-severity", "high", "Min template severity to run (critical, high, medium, low, info)")
	pocFlag := flag.String("poc", "", "Run gamma PoC(s): name(s) comma-separated, or '*' for all in --poc-dir")
	pocDir := flag.String("poc-dir", "./pocs/", "Path to gamma PoC directory")
	pocLevel := flag.Int("poc-level", 1, "Min PoC level to run: 1 all, 2 medium+, 3 critical/high only")
	pocTags := flag.String("poc-tags", "", "Run only PoCs whose tags contain any of these (comma-separated)")
	oobDomain := flag.String("oob-domain", "", "OOB DNS domain for {{dnslog}} (starts local DNS listener on :53; needs root)")

	clutchFlag := flag.Bool("clutch", false, "Detect race condition / TOCTOU vulnerabilities")
	apiSecurityFlag := flag.Bool("api-security", false, "Discover OpenAPI/Swagger specs and test API auth bypass")
	authLoginFlag := flag.String("auth-login", "", "Login page URL for authenticated scanning (auto-detects form, stores session cookies)")
	authUserFlag := flag.String("auth-user", "", "Username for --auth-login")
	authPassFlag := flag.String("auth-pass", "", "Password for --auth-login")
	authVerifyFlag := flag.String("auth-verify", "", "Optional URL to verify login succeeded (default: the login page itself)")
	snipeFlag := flag.Bool("snipe", false, "All modules attack single endpoint simultaneously (deep-dive)")
	strobeFlag := flag.Bool("strobe", false, "Full adaptive deep-dive pipeline (fingerprint → smart scan → chains → templates)")
	breachFlag := flag.Bool("breach", false, "Probe OAuth + SAML misconfigurations")
	grpcFlag := flag.Bool("grpc", false, "Probe gRPC reflection + REST gateway")

	flag.Usage = func() {
		fmt.Println("Usage: sxel -u <URL> [OPTIONS]")
		fmt.Println("Subcommands: proxy, recon, poclint, servicescan, reverse, burp-gamma, transform, genca, plugin, httpfuzzer, http (run: sxel <sub> --help)")
		fmt.Println()
		flag.PrintDefaults()
		fmt.Println(`
Examples:
  sxel -u "http://target.com/page?id=1"
  sxel -u "http://target.com" --crawl --waf-bypass
  sxel -u "http://target.com" --crawl --ws -o report.html
  sxel -u "http://target.com" --all --html-output report.html --json-output r.json
  sxel -u "http://target.com" --modules sqli --proxy http://127.0.0.1:8080
  sxel -l targets.txt --all --json-output results.json --list-concurrency 5
  sxel -u "http://target.com" -H "Authorization: Bearer xxx" -H "X-Api-Key: yyy"
  sxel -u "http://target.com" --jwt --cookie "session=abc; token=ey..."
  sxel -u "http://target.com" --graphql --idor --file-upload
  sxel -u "http://target.com" --all --checkpoint state.json
  sxel -u "http://target.com" --resume --checkpoint state.json`)
	}
	updateFlag := flag.Bool("update", false, "Update sxel to latest version")
	updateTemplatesFlag := flag.Bool("update-templates", false, "Update templates to latest version")
	convertNucleiFlag := flag.String("convert-nuclei", "", "Convert Nuclei templates from given directory to sxel format")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	configFlag := flag.String("config", "", "Path to sxel.yml config file (auto-detected in cwd if omitted)")
	initConfigFlag := flag.Bool("init-config", false, "Write a default sxel.yml template to ./sxel.yml and exit")
	profileFlag := flag.String("profile", "", "Scan profile: quick (fast passive), deep (everything), snipe (single-endpoint deep-dive)")
	sarifOut := flag.String("sarif-output", "", "Save SARIF 2.1.0 report (GitHub code scanning compatible)")
	stateFile := flag.String("state", "", "Findings state file: diff against previous run and store current fingerprints")
	webhookURL := flag.String("webhook", "", "Send scan summary to webhook URL (Slack/Discord/Telegram)")
	webhookType := flag.String("webhook-type", "slack", "Webhook format: slack, discord or telegram")
	webhookChatID := flag.String("webhook-chat-id", "", "Telegram chat_id (required for --webhook-type telegram)")

	moduleSetters := map[string]func(){
		"all":                func() { *allFlag = true },
		"sqli":               func() { *sqliFlag = true },
		"xss":                func() { *xssFlag = true },
		"blind":              func() { *blind = true },
		"header-scan":        func() { *headerScan = true },
		"cookie-scan":        func() { *cookieScan = true },
		"sensitive-files":    func() { *sensitiveFiles = true },
		"open-redirect":      func() { *openRedirect = true },
		"path-traversal":     func() { *pathTraversal = true },
		"security-headers":   func() { *securityHdrs = true },
		"cors":               func() { *corsScan = true },
		"http-methods":       func() { *httpMethods = true },
		"js-endpoints":       func() { *jsEndpoints = true },
		"ssti":               func() { *ssti = true },
		"crlf":               func() { *crlfScan = true },
		"host-header":        func() { *hostHeader = true },
		"json-injection":     func() { *jsonScan = true },
		"cmdi":               func() { *cmdInjection = true },
		"ssrf":               func() { *ssrfScan = true },
		"xxe":                func() { *xxeScan = true },
		"nosql":              func() { *nosqlScan = true },
		"dirscan":            func() { *dirScan = true },
		"file-upload":        func() { *fileUpload = true },
		"jwt":                func() { *jwtScan = true },
		"webshell":           func() { *webShellScan = true },
		"shell":              func() { *shellScan = true },
		"idor":               func() { *idorScan = true },
		"graphql":            func() { *graphqlScan = true },
		"csrf":               func() { *csrfScan = true },
		"cookie-audit":       func() { *cookieAuditFlag = true },
		"proto-pollution":    func() { *protoPollution = true },
		"deserialize":        func() { *deserializeFlag = true },
		"cache-poison":       func() { *cachePoisonFlag = true },
		"cache-deception":    func() { *cacheDeceptionFlag = true },
		"smuggling":          func() { *smugglingFlag = true },
		"hpp":                func() { *hppFlag = true },
		"dom-audit":          func() { *domAuditFlag = true },
		"lfi":                func() { *lfiFlag = true },
		"ldap-xpath":         func() { *ldxFlag = true },
		"h2c":                func() { *h2cFlag = true },
		"jarm":               func() { *jarmFlag = true },
		"dom":                func() { *domFlag = true },
		"mass-assign":        func() { *massFlag = true },
		"axfr":               func() { *axfrFlag = true },
		"subdomain-enum":     func() { *subdomainEnumFlag = true },
		"subdomain-takeover": func() { *subTakeoverFlag = true },
		"templates":          func() { *templatesFlag = true },
		"poc":                func() { *pocFlag = "*" },
		"ws":                 func() { *ws = true },
		"waf-detect":         func() { *wafDetect = true },
		"rate-limit-test":    func() { *rateLimitTestFlag = true },
		"clutch":             func() { *clutchFlag = true },
		"api-security":       func() { *apiSecurityFlag = true },
		"snipe":              func() { *snipeFlag = true },
		"strobe":             func() { *strobeFlag = true },
		"breach":             func() { *breachFlag = true },
		"grpc":               func() { *grpcFlag = true },
	}

	flag.Parse()

	var missing []string
	for _, name := range config.SetFiles() {
		if _, err := os.Stat(name); os.IsNotExist(err) {
			missing = append(missing, name)
		}
	}
	wantsConfig := len(missing) > 0 &&
		!*versionFlag && !*initConfigFlag && !*updateFlag && !*updateTemplatesFlag &&
		*convertNucleiFlag == ""
	if wantsConfig {
		output.Warn("config (%s) not found, generating", strings.Join(missing, ", "))
		for _, name := range missing {
			if tmpl, ok := config.Template(name); ok {
				output.Success("generating %s", name)
				if err := os.WriteFile(name, []byte(tmpl), 0o644); err != nil {
					output.Error("cannot write %s: %v", name, err)
					continue
				}
				for i := 0; i < 5; i++ {
					time.Sleep(time.Second)
					fmt.Print(".")
				}
				fmt.Printf(" done (5s) -> %s\n", name)
			}
		}
	}

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	if *initConfigFlag {
		if err := config.WriteTemplate("sxel.yml"); err != nil {
			output.Error("cannot write config template: %v", err)
			os.Exit(1)
		}
		output.Success("config template written to ./sxel.yml — edit it, then run sxel (auto-detected in cwd, or use --config)")
		os.Exit(0)
	}

	if strings.ToLower(*modulesFlag) == "help" {
		printModulesHelp(moduleSetters)
		os.Exit(0)
	}

	if *profileFlag != "" {
		if pf, ok := config.ProfileFlags(*profileFlag); ok {
			output.Info("profile %q: %s", *profileFlag, config.ProfileSummary(*profileFlag))
			explicit := map[string]bool{}
			flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
			for k, v := range pf {
				if !explicit[k] && flag.Lookup(k) != nil {
					flag.Set(k, v)
				}
			}
		} else {
			output.Warn("unknown profile %q (valid: %s)", *profileFlag, strings.Join(config.ValidProfiles(), ", "))
		}
	}
	var engCfg config.Engine
	if cfgPath := *configFlag; cfgPath != "" || config.Find() != "" {
		if cfgPath == "" {
			cfgPath = config.Find()
		}
		cf, err := config.Load(cfgPath)
		if err != nil {
			output.Error("cannot load config %s: %v", cfgPath, err)
		} else {
			companions := 0
			for _, p := range config.FindCompanions(filepath.Dir(cfgPath)) {
				cf2, cerr := config.Load(p)
				if cerr != nil {
					continue
				}
				config.Merge(cf, cf2)
				companions++
			}
			engCfg = cf.Engine
			explicit := map[string]bool{}
			flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
			applied := 0
			for k, v := range cf.FlagValues() {
				if !explicit[k] && flag.Lookup(k) != nil {
					if err := flag.Set(k, v); err != nil {
						output.Warn("config: ignoring invalid %s=%q: %v", k, v, err)
						continue
					}
					applied++
				}
			}
			if len(cf.Targets) > 0 && !explicit["u"] && !explicit["url"] && !explicit["list"] && !explicit["l"] {
				if len(cf.Targets) == 1 {
					flag.Set("u", cf.Targets[0])
				} else {
					tmp, terr := os.CreateTemp("", "sxel-targets-*.txt")
					if terr == nil {
						defer os.Remove(tmp.Name())
						for _, t := range cf.Targets {
							tmp.WriteString(t + "\n")
						}
						tmp.Close()
						flag.Set("list", tmp.Name())
					}
				}
			}
			msg := fmt.Sprintf("config %s applied (%d flag value(s) from file)", cfgPath, applied)
			if companions > 0 {
				msg += fmt.Sprintf(" + %d companion file(s)", companions)
			}
			output.Info("%s", msg)
		}
	}

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

	for i, t := range rawTargets {
		p, err := url.Parse(t)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https" &&
			p.Scheme != "ws" && p.Scheme != "wss") {
			output.Error("Invalid URL - must start with http://, https://, ws:// or wss://: %s", t)
			os.Exit(1)
		}
		if p.Scheme == "ws" {
			p.Scheme = "http"
			rawTargets[i] = p.String()
		} else if p.Scheme == "wss" {
			p.Scheme = "https"
			rawTargets[i] = p.String()
		}
	}

	headers, err := core.BuildHeaders(headerArgs, *headersFile)
	if err != nil {
		output.Error("%v", err)
		os.Exit(1)
	}

	if (*clientCert == "") != (*clientKey == "") {
		output.Error("--client-cert and --client-key must be used together")
		os.Exit(1)
	}
	if *clientCert != "" {
		if _, err := tls.LoadX509KeyPair(*clientCert, *clientKey); err != nil {
			output.Error("invalid client certificate/key: %v", err)
			os.Exit(1)
		}
	}

	explicitModule := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "header-scan", "cookie-scan", "sensitive-files", "open-redirect",
			"path-traversal", "security-headers", "cors", "http-methods",
			"js-endpoints", "ssti", "crlf", "host-header", "json-injection",
			"cmdi", "ssrf", "xxe", "nosql", "dirscan", "file-upload", "jwt",
			"webshell", "shell", "idor", "graphql", "csrf", "cookie-audit",
			"proto-pollution", "deserialize", "cache-poison", "cache-deception", "smuggling",
			"hpp", "dom-audit", "lfi", "ldap-xpath", "h2c", "jarm", "dom",
			"mass-assign", "axfr", "subdomain-enum", "subdomain-takeover",
			"templates", "ws", "rate-limit-test", "clutch", "poc",
			"snipe", "strobe", "breach", "grpc", "sqli", "xss", "modules":
			explicitModule = true
		}
	})
	if *allFlag {
		explicitModule = true
	}

	if *modulesFlag != "" {
		explicitModule = true
		if err := applyModules(*modulesFlag, moduleSetters); err != nil {
			output.Error("%v", err)
			os.Exit(1)
		}
		if *allFlag {
			explicitModule = true
		}
	}

	if *allFlag {
		*blind = true
		*ws = true
		*rateLimitTestFlag = true
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
		*webShellScan = true
		*csrfScan = true
		*cookieAuditFlag = true
		*subdomainEnumFlag = true
		*protoPollution = true
		*deserializeFlag = true
		*cachePoisonFlag = true
		*lfiFlag = true
		*hppFlag = true
		*domAuditFlag = true
		*ldxFlag = true
		*h2cFlag = true
		*jarmFlag = true
		*domFlag = true
		*massFlag = true
		*axfrFlag = true
		*smugglingFlag = true
		*cacheDeceptionFlag = true
		*subTakeoverFlag = true
		*templatesFlag = true
		*clutchFlag = true
		*apiSecurityFlag = true
		*snipeFlag = true
		*strobeFlag = true
		*breachFlag = true
		*grpcFlag = true
		if *pocFlag == "" {
			*pocFlag = "*"
		}
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
		URL:               target,
		Crawl:             *crawl,
		BasicCrawl:        *basicCrawl,
		JSCrawl:           *jsCrawl,
		Threads:           *threads,
		Timeout:           *timeout,
		WAFBypass:         *wafBypass,
		HTMLOutput:        *htmlOut,
		JSONOutput:        *jsonOut,
		CSVOutput:         *csvOut,
		EvidenceDir:       *evidenceDir,
		Recorder:          core.NewRecorder(512),
		Session:           core.NewSessionJar(*cookie),
		SQLScan:           *sqliFlag || *allFlag || !explicitModule,
		XSSScan:           *xssFlag || *allFlag || !explicitModule,
		Cookie:            *cookie,
		Headers:           headers,
		Delay:             *delay,
		UserAgent:         *userAgent,
		Proxy:             *proxy,
		Verbose:           *verbose,
		ClientCert:        *clientCert,
		ClientKey:         *clientKey,
		WS:                *ws,
		Exclude:           *exclude,
		MaxPages:          *maxPages,
		BlindSQLi:         *blind,
		MaxQueryVariants:  10,
		HandshakeTimeout:  0,
		SQLiMarginFactor:  0.7,
		SQLiConfirmFactor: 0.6,
		HeaderScan:        *headerScan,
		CookieScan:        *cookieScan,
		SensitiveFiles:    *sensitiveFiles,
		OpenRedirect:      *openRedirect,
		PathTraversal:     *pathTraversal,
		SecurityHdrs:      *securityHdrs,
		CORSScan:          *corsScan,
		HTTPMethods:       *httpMethods,
		JSEndpoints:       *jsEndpoints,
		SSTI:              *ssti,
		CRLFScan:          *crlfScan,
		HostHeader:        *hostHeader,
		JSONScan:          *jsonScan,
		AllChecks:         *allFlag,
		CmdInjection:      *cmdInjection,
		SSRFScan:          *ssrfScan,
		XXEScan:           *xxeScan,
		NoSQLScan:         *nosqlScan,
		RateLimit:         *rateLimit,
		DirScan:           *dirScan,
		Wordlist:          *wordlist,
		Scope:             scopePatterns,
		OutOfScope:        outOfScopePatterns,
		WAFAutoDetect:     *wafDetect,
		FileUpload:        *fileUpload,
		JWTScan:           *jwtScan,
		WebShell:          *webShellScan || *shellScan,
		IDORScan:          *idorScan,
		GraphQL:           *graphqlScan,
		CheckpointFile:    *checkpointFile,
		CSRF:              *csrfScan,
		CookieAudit:       *cookieAuditFlag,
		SubdomainEnum:     *subdomainEnumFlag,
		ProtoPollution:    *protoPollution,
		Deserialize:       *deserializeFlag,
		CachePoison:       *cachePoisonFlag,
		LFI:               *lfiFlag,
		HPP:               *hppFlag,
		DOMAudit:          *domAuditFlag,
		LDAPXPath:         *ldxFlag,
		H2C:               *h2cFlag,
		JARMScan:          *jarmFlag,
		DOMXSS:            *domFlag,
		MassAssign:        *massFlag,
		AXFR:              *axfrFlag,
		Smuggling:         *smugglingFlag,
		CacheDeception:    *cacheDeceptionFlag,
		RateLimitTest:     *rateLimitTestFlag,
		SubTakeover:       *subTakeoverFlag,
		Templates:         *templatesFlag,
		PocScan:           *pocFlag != "",
		PocNames:          *pocFlag,
		PocTags:           *pocTags,
		PocLevel:          *pocLevel,
		PocDir:            *pocDir,
		TemplateDir:       *templateDir,
		TemplateSeverity:  *templateSeverity,
		OOBDomain:         *oobDomain,
		Clutch:            *clutchFlag,
		APISecurity:       *apiSecurityFlag,
		Snipe:             *snipeFlag,
		Strobe:            *strobeFlag,
		Breach:            *breachFlag,
		Grpc:              *grpcFlag,
	}

	if engCfg.MaxQueryVariants != nil {
		cfg.MaxQueryVariants = *engCfg.MaxQueryVariants
	}
	if engCfg.HandshakeTimeout != nil {
		cfg.HandshakeTimeout = *engCfg.HandshakeTimeout
	}
	if engCfg.SQLiMarginFactor != nil {
		cfg.SQLiMarginFactor = *engCfg.SQLiMarginFactor
	}
	if engCfg.SQLiConfirmFactor != nil {
		cfg.SQLiConfirmFactor = *engCfg.SQLiConfirmFactor
	}
	if engCfg.MaxQueryVariants != nil || engCfg.HandshakeTimeout != nil ||
		engCfg.SQLiMarginFactor != nil || engCfg.SQLiConfirmFactor != nil {
		output.Info("engine config: max-query-variants=%d handshake-timeout=%ds sqli-margin=%.2f sqli-confirm=%.2f",
			cfg.MaxQueryVariants, cfg.HandshakeTimeout, cfg.SQLiMarginFactor, cfg.SQLiConfirmFactor)
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

	printModuleSummary(cfg)

	displayTarget := target
	if listPath != "" {
		displayTarget = fmt.Sprintf("%d targets from %s", len(rawTargets), listPath)
	} else if len(rawTargets) == 1 {
		displayTarget = rawTargets[0]
	}
	output.Info("Target: %s", displayTarget)
	if len(headers) > 0 {
		output.Info("Extra Headers: %d", len(headers))
	}
	if cfg.WAFBypass {
		output.Info("WAF Bypass: ENABLED")
	}
	if cfg.Crawl || cfg.BasicCrawl {
		mode := "deep (follows all links)"
		if cfg.BasicCrawl {
			mode = "basic (homepage only)"
		}
		output.Info("Crawl Mode: %s", mode)
	}
	if cfg.WS {
		output.Info("WebSocket: scan enabled")
	}
	if cfg.BlindSQLi && cfg.SQLScan {
		output.Info("Blind SQLi: enabled (slower due to time-based tests)")
	}

	var loadedTemplates []engine.Template
	var templatesVersion string
	var loadedPocs []*poc.PoC
	if cfg.PocScan {
		pocs, pErr := poc.LoadDir(cfg.PocDir)
		if pErr != nil {
			output.Warn("Cannot load PoCs from %q: %v", cfg.PocDir, pErr)
		} else if len(pocs) > 0 {
			loadedPocs = pocs
			output.Info("Loaded %d gamma PoC(s) from %s", len(pocs), cfg.PocDir)
		}
	}
	if cfg.Templates {
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

		if templatesVersion != "" {
			go func(localVer string) {
				latest := updater.FetchLatestTemplatesVersion()
				if latest != "" && latest != localVer {
					output.Warn("Templates %s available (you have %s) — run: sxel --update-templates", latest, localVer)
				}
			}(templatesVersion)
		}
	}

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

	var dnsOOB *engine.DNSOOB
	if cfg.OOBDomain != "" {
		dnsOOB, err = engine.NewDNSOOB(":53")
		if err != nil {
			output.Warn("Cannot start DNS OOB listener (port 53 may need root): %v", err)
		} else {
			defer dnsOOB.Close()
		}
	}

	client := core.NewHTTPClient(cfg)
	if cfg.Limiter != nil {
		defer cfg.Limiter.Close()
	}

	if *authLoginFlag != "" || *authUserFlag != "" || *authPassFlag != "" {
		ok, err := engine.Authenticate(client, cfg, engine.AuthConfig{
			LoginURL:  *authLoginFlag,
			Username:  *authUserFlag,
			Password:  *authPassFlag,
			VerifyURL: *authVerifyFlag,
		})
		if err != nil {
			output.Warn("authenticated scanning failed: %v — continuing unauthenticated", err)
		} else if ok {
			output.Info("authenticated session established — scanning with stored session cookies")
		} else {
			output.Warn("login did not yield an authenticated session — continuing unauthenticated")
		}
	}

	var allResults []core.ScanResult
	totalURLs := 0
	totalForms := 0

	if len(rawTargets) == 1 {
		fmt.Println()
		output.Info("Running site-wide checks...")
		res, urls, forms := scanTarget(client, cfg, rawTargets[0], *useRobots, loadedTemplates, loadedPocs, oobServer, dnsOOB, parseDirExts(*dirExt), *dirDepth, *dirContent)
		allResults = res
		totalURLs = urls
		totalForms = forms
	} else {
		fmt.Println()
		output.Info("Scanning %d targets from %s (concurrency %d)...", len(rawTargets), listPath, *listConcurrency)
		var mu sync.Mutex
		g, _ := errgroup.WithContext(context.Background())
		g.SetLimit(*listConcurrency)
		for _, t := range rawTargets {
			tg := t
			g.Go(func() error {
				cfgCopy := *cfg
				res, urls, forms := scanTarget(client, &cfgCopy, tg, *useRobots, loadedTemplates, loadedPocs, oobServer, dnsOOB, parseDirExts(*dirExt), *dirDepth, *dirContent)
				mu.Lock()
				allResults = append(allResults, res...)
				totalURLs += urls
				totalForms += forms
				mu.Unlock()
				return nil
			})
		}
		g.Wait()
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

	writeReports(cfg, allResults)
	if *mdOut != "" {
		writeMDReport(*mdOut, allResults)
	}
	findings := report.FromScanResults(allResults)
	if *sarifOut != "" {
		if err := report.WriteSARIF(*sarifOut, findings, version.Current); err != nil {
			output.Error("SARIF report: %v", err)
		} else {
			output.Success("SARIF report -> %s", *sarifOut)
		}
	}
	if *stateFile != "" {
		if prev, err := report.LoadState(*stateFile); err == nil {
			d := report.Compare(prev.Findings, findings)
			if len(d.Added)+len(d.Fixed)+len(d.Changed) > 0 {
				output.Separator()
				output.Info("scan diff vs previous state: +%d new, -%d fixed, ~%d changed, %d unchanged",
					len(d.Added), len(d.Fixed), len(d.Changed), d.Same)
				for _, f := range d.Added {
					output.VulnInline("NEW", "%s %s [%s]", f.Type, f.URL, f.Severity)
				}
				for _, f := range d.Fixed {
					output.Success("FIXED: %s %s", f.Type, f.URL)
				}
				for _, f := range d.Changed {
					output.Warn("CHANGED: %s %s (%s)", f.Type, f.URL, f.Severity)
				}
			} else {
				output.Info("scan diff vs previous state: no changes (%d findings)", d.Same)
			}
		} else if !os.IsNotExist(err) {
			output.Error("cannot load state %s: %v", *stateFile, err)
		}
		if err := report.SaveState(*stateFile, findings); err != nil {
			output.Error("cannot save state %s: %v", *stateFile, err)
		} else {
			output.Success("scan state -> %s", *stateFile)
		}
	}
	if *webhookURL != "" {
		title := fmt.Sprintf("sxel scan finished: %d finding(s)", len(findings))
		if err := report.SendWebhook(*webhookURL, *webhookType, *webhookChatID, title, findings, 10*time.Second); err != nil {
			output.Error("webhook: %v", err)
		} else {
			output.Success("webhook delivered (%s)", *webhookType)
		}
	}
}

func printModuleSummary(cfg *core.Config) {
	var mods []string
	add := func(name string, enabled bool) {
		if enabled {
			mods = append(mods, name)
		}
	}
	add("SQLi", cfg.SQLScan)
	add("BlindSQLi", cfg.BlindSQLi && cfg.SQLScan)
	add("XSS", cfg.XSSScan)
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
	add("WebShell", cfg.WebShell)
	add("IDOR", cfg.IDORScan)
	add("GraphQL", cfg.GraphQL)
	add("CSRF", cfg.CSRF)
	add("CookieAudit", cfg.CookieAudit)
	add("SubdomainEnum", cfg.SubdomainEnum)
	add("ProtoPollution", cfg.ProtoPollution)
	add("Deserialize", cfg.Deserialize)
	add("CachePoison", cfg.CachePoison)
	add("Smuggling", cfg.Smuggling)
	add("CacheDeception", cfg.CacheDeception)
	add("RateLimitTest", cfg.RateLimitTest)
	add("HPP", cfg.HPP)
	add("DOMAudit", cfg.DOMAudit)
	add("LDAPXPath", cfg.LDAPXPath)
	add("H2C", cfg.H2C)
	add("JARM", cfg.JARMScan)
	add("DOMXSS", cfg.DOMXSS)
	add("MassAss", cfg.MassAssign)
	add("AXFR", cfg.AXFR)
	add("SubTakeover", cfg.SubTakeover)
	add("WebSocket", cfg.WS)
	add("WAFBypass", cfg.WAFBypass)
	add("Clutch", cfg.Clutch)
	add("APISecurity", cfg.APISecurity)
	add("Snipe", cfg.Snipe)
	add("Strobe", cfg.Strobe)
	add("Breach", cfg.Breach)
	add("Grpc", cfg.Grpc)
	add("Templates", cfg.Templates)
	add("PoC", cfg.PocScan)

	output.Info("Loaded %d scan module(s)", len(mods))
	if len(mods) > 0 {
		output.Info("Enabled: %s", strings.Join(mods, ", "))
	}
}

func runPocs(client *http.Client, cfg *core.Config, targetURL string, pocs []*poc.PoC) []core.ScanResult {
	var results []core.ScanResult
	var names, tags []string
	if cfg.PocNames != "" && cfg.PocNames != "*" {
		for _, n := range strings.Split(cfg.PocNames, ",") {
			names = append(names, strings.TrimSpace(n))
		}
	}
	if cfg.PocTags != "" {
		for _, t := range strings.Split(cfg.PocTags, ",") {
			tags = append(tags, strings.TrimSpace(t))
		}
	}
	level := cfg.PocLevel
	if level <= 0 {
		level = 1
	}
	for _, p := range pocs {
		if len(names) > 0 && !containsString(names, p.Name) {
			continue
		}
		if len(tags) > 0 && !hasAnyTag(p.Detail.Tags, tags) {
			continue
		}
		if pocLevelRank(p.Severity()) < level {
			continue
		}
		if cfg.Verbose {
			output.Verbose("[poc] %s -> %s", p.Name, targetURL)
		}
		matched, resp, err := p.Run(client, targetURL)
		if err != nil {
			output.Verbose("[poc] %s error: %v", p.Name, err)
			continue
		}
		if matched {
			res := p.ToResult(targetURL, resp)
			results = append(results, res)
			output.Success("[poc] %s (%s): %s", p.Name, res.Severity, targetURL)
		}
	}
	return results
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func hasAnyTag(pocTags string, want []string) bool {
	have := map[string]bool{}
	for _, t := range strings.Split(pocTags, ",") {
		have[strings.TrimSpace(t)] = true
	}
	for _, w := range want {
		if have[w] {
			return true
		}
	}
	return false
}

func pocLevelRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func scanTarget(client *http.Client, cfg *core.Config, target string, useRobots bool, templates []engine.Template, pocs []*poc.PoC, oobServer *engine.OOBServer, dnsOOB *engine.DNSOOB, dirExts []string, dirDepth int, dirContent bool) ([]core.ScanResult, int, int) {
	var allResults []core.ScanResult
	var mu sync.Mutex

	var reqSent, reqFailed, reqTotalNS int64
	client = core.NewCountingClient(client, &reqSent, &reqFailed, &reqTotalNS)

	if cfg.WAFAutoDetect {
		wafResult := modules.AutoDetectWAF(client, cfg, target)
		if wafResult.Detected {
			output.Warn("WAF detected: %s (%s)", wafResult.Vendor, wafResult.Evidence)
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

	if useRobots {
		seedURLs = append(seedURLs, engine.ParseRobotsTxt(client, cfg, target)...)
		seedURLs = append(seedURLs, engine.ParseSitemap(client, cfg, target)...)
		if tu, err := url.Parse(target); err == nil {
			filtered := seedURLs[:0]
			for _, su := range seedURLs {
				if suURL, err := url.Parse(su); err == nil && engine.SameSiteOrSubdomain(suURL.Host, tu.Host) {
					filtered = append(filtered, su)
				}
			}
			seedURLs = filtered
		}
		if cfg.MaxPages > 0 && len(seedURLs) > cfg.MaxPages {
			if cfg.Verbose {
				output.Verbose("[crawl] truncating %d seed(s) to --max-pages budget (%d)", len(seedURLs), cfg.MaxPages)
			}
			seedURLs = seedURLs[:cfg.MaxPages]
		}
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
	var livePrinted int64
	mu.Lock()
	livePrinted = int64(len(allResults))
	mu.Unlock()
	var curMu sync.Mutex
	var curSeq int64
	active := make(map[string]int64)
	var curURL string

	markActive := func(u string) {
		curMu.Lock()
		curSeq++
		active[u] = curSeq
		curURL = u
		curMu.Unlock()
	}

	markIdle := func(u string) {
		curMu.Lock()
		delete(active, u)
		curURL = ""
		best := int64(0)
		for url, s := range active {
			if s > best {
				best = s
				curURL = url
			}
		}
		curMu.Unlock()
	}

	livePrint := func(local []core.ScanResult) {
		if len(local) == 0 {
			return
		}
		mu.Lock()
		allResults = append(allResults, local...)
		atomic.AddInt64(&livePrinted, int64(len(local)))
		mu.Unlock()
		for _, f := range local {
			printFinding(cfg, f)
		}
	}

	go func() {
		tick := time.NewTicker(8 * time.Second)
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
				curMu.Lock()
				cur := curURL
				curMu.Unlock()
				output.Progress(done, n-done, sent, lat, fp, cur)
			}
		}
	}()

	scanSigMu := &sync.Mutex{}
	scannedSigs := make(map[string]bool)
	testedFormMu := &sync.Mutex{}
	testedForms := make(map[string]bool)
	formKey := func(f core.Form) string {
		names := make([]string, 0, len(f.Inputs))
		for _, in := range f.Inputs {
			names = append(names, in.Name)
		}
		sort.Strings(names)
		return f.Method + "|" + f.Action + "|" + strings.Join(names, ",")
	}
	targetSig := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		names := make([]string, 0, len(u.Query()))
		for k := range u.Query() {
			names = append(names, k)
		}
		sort.Strings(names)
		return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.Path + "|" + strings.Join(names, ",")
	}

	scanPage := func(t core.CrawlResult) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { atomic.AddInt64(&doneCount, 1) }()
			markActive(t.URL)
			defer func() { markIdle(t.URL) }()

			sig := targetSig(t.URL)
			scanSigMu.Lock()
			sigDup := scannedSigs[sig]
			if !sigDup {
				scannedSigs[sig] = true
			}
			scanSigMu.Unlock()
			if sigDup {
				if cfg.Verbose {
					output.Verbose("[skip] %s (param signature already scanned)", t.URL)
				}
				return
			}

			if len(t.Forms) > 0 {
				keep := make([]core.Form, 0, len(t.Forms))
				for _, f := range t.Forms {
					k := formKey(f)
					testedFormMu.Lock()
					if testedForms[k] {
						testedFormMu.Unlock()
						continue
					}
					testedForms[k] = true
					testedFormMu.Unlock()
					keep = append(keep, f)
				}
				t.Forms = keep
			}

			label := t.URL
			if len(t.Forms) > 0 {
				label = fmt.Sprintf("%s (+%d form(s))", t.URL, len(t.Forms))
			}
			output.Processing("GET", label)

			if cfg.Checkpoint.IsScanned(t.URL) {
				if cfg.Verbose {
					output.Verbose("[skip] %s (already scanned)", t.URL)
				}
				return
			}
			if cfg.Delay > 0 {
				time.Sleep(time.Duration(cfg.Delay) * time.Millisecond)
			}

			var local []core.ScanResult

			if cfg.Strobe {
				local = modules.ScanStrobe(client, cfg, t, templates)
				cfg.Checkpoint.MarkScanned(t.URL, local)
				livePrint(local)
				return
			}

			if cfg.Snipe {
				local = runSnipe(client, cfg, t.URL, templates)
				cfg.Checkpoint.MarkScanned(t.URL, local)
				livePrint(local)
				return
			}

			runSQL := cfg.SQLScan
			runXSS := cfg.XSSScan
			if runSQL {
				local = append(local, modules.ScanSQLi(client, cfg, t)...)
				if cfg.BlindSQLi {
					local = append(local, modules.ScanBlindSQLiTime(client, cfg, t)...)
					local = append(local, modules.ScanBooleanBlindSQLi(client, cfg, t)...)
				}
			}
			if runXSS {
				local = append(local, modules.ScanXSS(client, cfg, t)...)
				local = append(local, modules.ScanStoredXSS(client, cfg, t)...)
			}
			local = append(local, modules.Scan403Bypass(client, cfg, t)...)
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
			if oobServer != nil && (cfg.SSRFScan || cfg.XXEScan || cfg.CmdInjection) {
				local = append(local, engine.RunOOBProbes(client, cfg, t.URL, oobServer, dnsOOB)...)
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
			if cfg.WebShell {
				local = append(local, modules.ScanWebShell(client, cfg, t)...)
			}
			if cfg.IDORScan {
				local = append(local, modules.ScanIDOR(client, cfg, t)...)
			}
			if cfg.CSRF {
				local = append(local, modules.ScanCSRF(client, cfg, t)...)
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
			if cfg.HPP {
				local = append(local, modules.ScanHPP(client, cfg, t)...)
			}
			if cfg.DOMAudit {
				local = append(local, modules.ScanDOMAudit(client, cfg, t.URL)...)
			}
			if cfg.LDAPXPath {
				local = append(local, modules.ScanLDAPXPath(client, cfg, t)...)
			}
			if cfg.H2C {
				local = append(local, modules.ScanH2C(client, cfg, t.URL)...)
			}
			if cfg.JARMScan {
				local = append(local, modules.ScanJARM(client, cfg, t.URL)...)
			}
			if cfg.DOMXSS {
				local = append(local, modules.ScanDOMXSS(client, cfg, t)...)
			}
			if cfg.MassAssign {
				local = append(local, modules.ScanMassAssignment(client, cfg, t)...)
			}
			if cfg.AXFR {
				local = append(local, modules.ScanAXFR(client, cfg, t.URL, "")...)
			}
			if cfg.Smuggling {
				local = append(local, modules.ScanSmuggling(client, cfg, t)...)
			}
			if cfg.CachePoison {
				local = append(local, modules.ScanCachePoison(client, cfg, t)...)
			}
			if cfg.CacheDeception {
				local = append(local, modules.ScanCacheDeception(client, cfg, t)...)
			}
			if cfg.Clutch {
				local = append(local, modules.ScanClutch(client, cfg, t)...)
			}
			if cfg.APISecurity {
				local = append(local, modules.ScanAPISecurity(client, cfg, t)...)
			}
			if cfg.Breach {
				local = append(local, modules.ScanBreach(client, cfg, t)...)
			}
			if cfg.Grpc {
				local = append(local, modules.ScanGrpc(client, cfg, t)...)
			}
			if cfg.Templates && len(templates) > 0 {
				tmplBody, _, _ := core.DoGET(client, cfg, t.URL)
				fp := engine.FingerprintTarget(tmplBody, modules.ExtractResponseHeaders(client, cfg, t.URL), t.URL)
				filtered := engine.FilterTemplatesByTech(templates, fp.Tech)
				local = append(local, engine.RunTemplates(client, cfg, t.URL, filtered)...)
			}
			if cfg.PocScan && len(pocs) > 0 {
				local = append(local, runPocs(client, cfg, t.URL, pocs)...)
			}
			cfg.Checkpoint.MarkScanned(t.URL, local)
			livePrint(local)
		}()
	}

	crawlDone := make(chan struct{})
	seenForms := make(map[string]bool)
	go func() {
		defer close(crawlDone)
		if crawlEnabled {
			cr := engine.NewCrawler(client, cfg)
			cr.OnPage = func(page core.CrawlResult, n int) {
				var keep []core.Form
				for _, f := range page.Forms {
					k := formKey(f)
					if seenForms[k] {
						continue
					}
					seenForms[k] = true
					keep = append(keep, f)
				}
				page.Forms = keep
				targetsMu.Lock()
				targets = append(targets, page)
				totalForms += len(page.Forms)
				targetsMu.Unlock()
				pageChan <- page
			}
			cr.Crawl(target)
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
			targetsMu.Lock()
			targets = []core.CrawlResult{{URL: target, Forms: fs}}
			totalForms = len(fs)
			targetsMu.Unlock()
			for _, t := range targets {
				pageChan <- t
			}
			for _, su := range seedURLs {
				if su == target {
					continue
				}
				sf, _ := engine.FetchForms(client, cfg, su)
				p := core.CrawlResult{URL: su, Forms: sf}
				targetsMu.Lock()
				targets = append(targets, p)
				totalForms += len(p.Forms)
				targetsMu.Unlock()
				pageChan <- p
			}
		}
		if cfg.JSEndpoints {
			eps := engine.ExtractJSEndpoints(client, cfg, target)
			for _, ep := range eps {
				if tURL, err := url.Parse(target); err == nil {
					if epURL, err := url.Parse(ep); err == nil && !engine.SameSiteOrSubdomain(epURL.Host, tURL.Host) {
						continue
					}
				}
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
		sem <- struct{}{}
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
		allResults = append(allResults, modules.ScanDirsV2(client, cfg, target,
			modules.DirScanOpts{Exts: dirExts, Depth: dirDepth, ContentCheck: dirContent})...)
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

	mu.Lock()
	rest := allResults[int(atomic.LoadInt64(&livePrinted)):]
	mu.Unlock()
	if len(rest) > 0 {
		fmt.Printf("\r\033[K")
		printResults(cfg, rest)
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
	attachEvidence(cfg, results)
	if cfg.EvidenceDir != "" {
		dumpEvidenceFiles(cfg.EvidenceDir, results)
	}
	for i := range results {
		results[i] = modules.EscalateSeverity(results[i])
	}
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

func attachEvidence(cfg *core.Config, results []core.ScanResult) {
	if cfg.Recorder == nil {
		return
	}
	for i := range results {
		if results[i].Request != "" {
			continue
		}
		if ex := cfg.Recorder.Match(results[i].Method, results[i].URL); ex != nil {
			results[i].Request = ex.Request
			results[i].Response = ex.Response
		}
	}
}

func sanitizeFileName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "finding"
	}
	return out
}

func dumpEvidenceFiles(dir string, results []core.ScanResult) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		output.Error("evidence dir: %v", err)
		return
	}
	written := 0
	for i, r := range results {
		if r.Request == "" {
			continue
		}
		base := fmt.Sprintf("%s/%03d-%s-%s", dir, i, sanitizeFileName(r.Type), sanitizeFileName(r.Parameter))
		if err := os.WriteFile(base+".req", []byte(r.Request), 0o644); err != nil {
			output.Error("evidence write: %v", err)
			return
		}
		if err := os.WriteFile(base+".resp", []byte(r.Response), 0o644); err != nil {
			output.Error("evidence write: %v", err)
			return
		}
		written++
	}
	if written > 0 {
		output.Success("Evidence dumped: %d finding(s) -> %s", written, dir)
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
			`<tr class="finding"><td class="%s">[%s]</td><td>%s %s</td><td>%s</td><td>%s</td></tr>`,
			cls, r.Severity, escHTML(r.Method), escHTML(r.URL), escHTML(r.Evidence), evidenceDetailsHTML(r)))
	}
	io.WriteString(f, "</table></body></html>")
	output.Success("HTML report -> %s", path)
}

func evidenceDetailsHTML(r core.ScanResult) string {
	if r.Request == "" && r.Response == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<details><summary>request/response</summary><pre>`)
	b.WriteString(escHTML(r.Request))
	if r.Response != "" {
		b.WriteString("\n\n===== response =====\n\n")
		b.WriteString(escHTML(r.Response))
	}
	b.WriteString(`</pre></details>`)
	return b.String()
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

func printFinding(cfg *core.Config, r core.ScanResult) {
	output.PrintFinding(output.Finding{
		Type: r.Type, URL: r.URL, Method: r.Method,
		Parameter: r.Parameter, Payload: r.Payload,
		Severity: r.Severity, Evidence: r.Evidence,
		Timestamp: r.Timestamp.Format("2006-01-02 15:04:05"),
		ParamKey:  r.ParamKey, ParamValue: r.ParamValue,
		Position: r.Position, Extra: r.Extra,
	})
	if cfg.Verbose {
		spew.Dump(r)
	}
}

func printResults(cfg *core.Config, results []core.ScanResult) {
	for _, r := range results {
		printFinding(cfg, r)
	}
}

func runSnipe(client *http.Client, cfg *core.Config, targetURL string, templates []engine.Template) []core.ScanResult {
	target := core.CrawlResult{URL: targetURL}
	var allResults []core.ScanResult
	var mu sync.Mutex

	output.Info("Snipe mode: deep-dive scanning %s", targetURL)

	type snipeMod struct {
		name string
		fn   func(*http.Client, *core.Config, core.CrawlResult) []core.ScanResult
	}

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
		{"JARM", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.ScanJARM(c, cf, targetURL)
		}},
	}

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
		{"WebShell", modules.ScanWebShell},
		{"IDOR", modules.ScanIDOR},
		{"MassAssign", modules.ScanMassAssignment},
		{"AXFR", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.ScanAXFR(c, cf, t.URL, "")
		}},
		{"CSRF", func(c *http.Client, cf *core.Config, t core.CrawlResult) []core.ScanResult {
			return modules.ScanCSRF(c, cf, t)
		}},
		{"FileUpload", modules.ScanFileUpload},
		{"Deserialize", modules.ScanDeserialize},
		{"ProtoPollution", modules.ScanProtoPollution},
		{"CachePoison", modules.ScanCachePoison},
		{"Smuggling", modules.ScanSmuggling},
		{"Clutch", modules.ScanClutch},
		{"HPP", modules.ScanHPP},
	}

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

	if len(templates) > 0 {
		body, _, _ := core.DoGET(client, cfg, targetURL)
		fp := engine.FingerprintTarget(body, modules.ExtractResponseHeaders(client, cfg, targetURL), targetURL)
		filtered := engine.FilterTemplatesByTech(templates, fp.Tech)
		if len(filtered) > 0 {
			output.Info("Snipe: running %d/%d template(s) for detected tech %v", len(filtered), len(templates), fp.Tech)
			allResults = append(allResults, engine.RunTemplates(client, cfg, targetURL, filtered)...)
		}
	}

	return allResults
}

func csvEscape(s string) string {
	if len(s) > 0 && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@') {
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func parseDirExts(raw string) []string {
	var out []string
	for _, e := range strings.Split(raw, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}
