package modules

import (
	"bufio"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/color"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var BuiltinWordlist = []string{
	"admin", "admin/", "admin/login", "admin/dashboard", "admin/panel",
	"administrator", "administrator/", "login", "login.php", "login.html",
	"logout", "signup", "register", "dashboard", "panel", "cp", "backend",
	"console", "manage", "management", "control",
	"wp-admin", "wp-admin/", "wp-login.php", "wp-config.php",
	"wp-content", "wp-includes", "xmlrpc.php", "wp-cron.php",
	"phpmyadmin", "phpmyadmin/", "myadmin", "phpMyAdmin",
	"joomla", "drupal", "magento", "prestashop",
	"api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/", "api/v3",
	"api/admin", "api/user", "api/users", "api/auth", "api/login",
	"v1", "v2", "v3", "graphql", "graphiql", "rest", "rpc",
	"swagger", "swagger-ui", "swagger-ui/", "swagger.json", "swagger.yaml",
	"openapi.json", "openapi.yaml", "api-docs", "api-docs/",
	"actuator", "actuator/", "actuator/health", "actuator/env",
	"actuator/mappings", "actuator/beans", "actuator/info",
	"actuator/metrics", "actuator/logfile", "actuator/httptrace",
	"health", "healthz", "health/", "status", "ping", "version",
	"info", "metrics", "debug", "trace", "ready", "readyz",
	"upload", "uploads", "uploads/", "files", "files/", "media",
	"media/", "static", "assets", "assets/", "public", "public/",
	"download", "downloads", "images", "img", "js", "css",
	".env", ".env.local", ".env.production", ".env.development",
	".env.example", ".env.backup",
	"config", "config.php", "config.yml", "config.yaml", "config.json",
	"configuration", "settings", "settings.php",
	"secrets", "secret", "keys", "key", "credentials",
	".git/HEAD", ".git/config", ".gitignore", ".gitmodules",
	".svn/entries", ".hg/hgrc",
	"Dockerfile", ".dockerenv", ".docker-compose.yml",
	"docker-compose.yml", "docker-compose.yaml",
	".travis.yml", ".circleci/config.yml", ".github",
	"Makefile", "composer.json", "package.json", "package-lock.json",
	"yarn.lock", "Gemfile", "requirements.txt", "go.mod",
	"backup", "backup.zip", "backup.tar.gz", "backup.sql",
	"dump.sql", "db.sql", "database.sql", "data.sql", "old",
	"archive", "bak",
	"shell.php", "cmd.php", "webshell.php", "c99.php", "r57.php",
	"b374k.php", "mini.php", "test.php", "info.php", "phpinfo.php",
	"server-status", "server-info", ".htaccess", ".htpasswd",
	"web.config", "Web.config", "nginx.conf", "apache2.conf",
	"cgi-bin", "cgi-bin/", "bin",
	"robots.txt", "sitemap.xml", "sitemap.xml.gz",
	".well-known/", ".well-known/security.txt",
	"crossdomain.xml", "clientaccesspolicy.xml",
	"favicon.ico", "apple-touch-icon.png",
	"auth", "oauth", "oauth2", "saml", "sso", "cas",
	"token", "tokens", "session", "sessions",
	"test", "tests", "dev", "development", "staging", "uat",
	"demo", "sandbox", "tmp", "temp", "cache", "logs", "log",
	"install.php", "setup.php", "install.sql", "setup",
	"user", "users", "account", "accounts", "members", "member",
	"profile", "internal", "private", "error", "500", "404",
	"README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md",
}

type DirScanResult struct {
	URL           string
	Status        int
	ContentLength int
	ContentType   string
}

type DirScanOpts struct {
	Exts         []string
	Depth        int
	ContentCheck bool
}

func ScanDirs(client *http.Client, cfg *core.Config, target string) []core.ScanResult {
	return ScanDirsV2(client, cfg, target, DirScanOpts{})
}

func ScanDirsV2(client *http.Client, cfg *core.Config, target string, opts DirScanOpts) []core.ScanResult {
	wordlist, err := loadWordlist(cfg.Wordlist)
	if err != nil {
		output.Error("Cannot load wordlist %q: %v — falling back to built-in \n", cfg.Wordlist, err)
		wordlist = BuiltinWordlist
	}

	base, err := url.Parse(target)
	if err != nil {
		return nil
	}
	base.Path = "/"
	base.RawQuery = ""
	base.Fragment = ""
	baseStr := strings.TrimRight(base.String(), "/")

	output.Info("[*] DirScan     : %s (%d paths, %d workers, ext=%v, depth=%d, content-check=%v)\n",
		baseStr, len(wordlist), cfg.Threads, opts.Exts, opts.Depth, opts.ContentCheck)

	type job struct {
		base  string
		path  string
		depth int
	}
	words := make([]string, 0, len(wordlist))
	for _, p := range wordlist {
		words = append(words, strings.TrimLeft(p, "/"))
	}

	workers := cfg.Threads
	if workers <= 0 {
		workers = 10
	}

	var (
		mu         sync.Mutex
		baselineMu sync.Mutex
		baselines  = map[string][2]int{}
		hits       []DirScanResult
		results    []core.ScanResult
		wg         sync.WaitGroup
		producerWG sync.WaitGroup
		jobs       = make(chan job, workers*2)
		done       = make(chan struct{})
	)
	baselineFor := func(baseStr string) (int, int) {
		baselineMu.Lock()
		if b, ok := baselines[baseStr]; ok {
			baselineMu.Unlock()
			return b[0], b[1]
		}
		baselineMu.Unlock()
		randPath := fmt.Sprintf("/sxel-dirscan-baseline-%d", rand.Int63n(9999999))
		var baseStatus, baseLen int
		for attempt := 0; attempt < 3; attempt++ {
			baseStatus, baseLen, _ = dirProbe(client, cfg, baseStr+randPath)
			if baseStatus != 0 {
				break
			}
		}
		if baseStatus == 0 {
			output.Warn("Dirscan: baseline probe failed for %s — path results may be unreliable", baseStr)
		}
		baselineMu.Lock()
		baselines[baseStr] = [2]int{baseStatus, baseLen}
		baselineMu.Unlock()
		return baseStatus, baseLen
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				case j := <-jobs:
					probeURL := j.base + "/" + j.path
					status, cLen, cType := dirProbe(client, cfg, probeURL)

					if status == 0 || status == 404 {
						producerWG.Done()
						continue
					}
					bs, bl := baselineFor(j.base)
					if bs != 0 && status == bs && absInt(cLen-bl) < maxInt(100, bl/10) {
						producerWG.Done()
						continue
					}
					hit := DirScanResult{
						URL: probeURL, Status: status,
						ContentLength: cLen, ContentType: cType,
					}
					mu.Lock()
					hits = append(hits, hit)
					mu.Unlock()
					label := statusLabel(status)
					fmt.Printf("\r  %s [%d] %s (%d bytes)%-20s\n",
						label, status, probeURL, cLen, "")

					if opts.Depth > 0 && j.depth > 0 &&
						(status == 301 || status == 302 || status == 307 ||
							(status == 200 && strings.HasSuffix(probeURL, "/"))) {
						sub := strings.TrimRight(probeURL, "/")
						for _, w := range words {
							producerWG.Add(1)
							select {
							case jobs <- job{base: sub, path: w, depth: j.depth - 1}:
							default:
								producerWG.Done()
							}
						}
					}
					if opts.ContentCheck && sensitiveFile(j.path) {
						for _, r := range contentCheck(client, cfg, probeURL) {
							mu.Lock()
							results = append(results, r)
							mu.Unlock()
						}
					}
					producerWG.Done()
				}
			}
		}()
	}
	producerWG.Add(2)
	jobs <- job{base: baseStr, path: "", depth: opts.Depth + 1}
	go func() {
		producerWG.Wait()
		close(done)
	}()
	go func() {
		defer producerWG.Done()
		for _, w := range words {
			if strings.Contains(w, "*") || strings.Contains(w, "?") {
				continue
			}
			producerWG.Add(1)
			jobs <- job{base: baseStr, path: w, depth: opts.Depth}
			for _, ext := range opts.Exts {
				if !strings.Contains(w, ".") && !strings.HasSuffix(w, "/") {
					producerWG.Add(1)
					jobs <- job{base: baseStr, path: w + ext, depth: 0}
				}
			}
		}
	}()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	for _, h := range hits {
		sev := dirSeverity(h.Status, h.URL)
		results = append([]core.ScanResult{{
			Type:      "Directory / File Found",
			URL:       h.URL,
			Method:    "GET",
			Parameter: "-",
			Payload:   "-",
			Severity:  sev,
			Evidence: fmt.Sprintf("HTTP %d | %d bytes | %s",
				h.Status, h.ContentLength, h.ContentType),
			Timestamp: time.Now(),
		}}, results...)
	}

	output.Info("[*] DirScan     : %d path(s) found\n", len(hits))
	return results
}

func dirProbe(client *http.Client, cfg *core.Config, rawURL string) (int, int, string) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return 0, 0, ""
	}
	core.ApplyHeaders(req, cfg)
	probeClient := *client
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := probeClient.Do(req)
	if err != nil {
		return 0, 0, ""
	}
	defer resp.Body.Close()

	bodyLen := len(core.ReadBody(resp.Body))
	ct := resp.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i != -1 {
		ct = strings.TrimSpace(ct[:i])
	}
	return resp.StatusCode, bodyLen, ct
}

func dirSeverity(status int, rawURL string) string {
	pathLow := strings.ToLower(rawURL)
	sensKeywords := []string{
		".env", ".git", "config", "backup", "dump", "secret",
		"admin", "shell.php", "cmd.php", "phpinfo", "actuator",
		"credentials", "password", ".htpasswd", "web.config",
	}
	for _, kw := range sensKeywords {
		if strings.Contains(pathLow, kw) {
			return "HIGH"
		}
	}
	switch {
	case status == 200:
		return "MEDIUM"
	case status == 301 || status == 302 || status == 307:
		return "INFO"
	case status == 403:
		return "LOW"
	default:
		return "INFO"
	}
}

func statusLabel(status int) string {
	switch {
	case status == 200:
		return color.Green("[+]")
	case status == 301 || status == 302 || status == 307:
		return color.Yellow("[~]")
	case status == 403:
		return color.Yellow("[!]")
	default:
		return color.Gray("[?]")
	}
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var sensitiveExts = []string{".bak", ".swp", ".sql", ".log", ".conf", ".config",
	".json", ".yml", ".yaml", ".txt", ".php", ".ini", ".xml", ".gz", ".zip",
	".env", ".sh", ".py", ".pl", ".rb", ".js", ".ts", ".pem", ".key"}

func sensitiveFile(path string) bool {
	lower := strings.ToLower(path)
	kw := []string{".git", "dump", "backup", "secret", "credentials",
		".htpasswd", "web.config", "password", "id_rsa"}
	for _, k := range kw {
		if strings.Contains(lower, k) {
			return true
		}
	}
	for _, e := range sensitiveExts {
		if strings.HasSuffix(lower, e) {
			return true
		}
	}
	return false
}

type secretRule struct {
	kind string
	re   *regexp.Regexp
}

var secretRules = []secretRule{
	{"AWS access key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"AWS secret key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"GitHub token", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"OpenAI key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{"Private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{"JWT token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{"Database URL", regexp.MustCompile(`(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^\s"'` + "`" + `]+`)},
	{"Password assignment", regexp.MustCompile(`(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["'][^"']{4,}["']`)},
}

func contentCheck(client *http.Client, cfg *core.Config, rawURL string) []core.ScanResult {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	core.ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body := core.ReadBody(resp.Body)
	if len(body) > 1<<19 {
		body = body[:1<<19]
	}
	var out []core.ScanResult
	seen := map[string]bool{}
	for _, rule := range secretRules {
		m := rule.re.FindString(string(body))
		if m == "" || seen[rule.kind] {
			continue
		}
		seen[rule.kind] = true
		snippet := m
		if len(snippet) > 60 {
			snippet = snippet[:60]
		}
		out = append(out, core.ScanResult{
			Type:      "Secret in Exposed File",
			URL:       rawURL,
			Method:    "GET",
			Parameter: "-",
			Payload:   rule.kind,
			Severity:  "HIGH",
			Evidence:  fmt.Sprintf("%s: %s...", rule.kind, snippet),
			Timestamp: time.Now(),
		})
	}
	return out
}

func loadWordlist(path string) ([]string, error) {
	if path == "" {
		return BuiltinWordlist, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return BuiltinWordlist, nil
	}
	return lines, sc.Err()
}
