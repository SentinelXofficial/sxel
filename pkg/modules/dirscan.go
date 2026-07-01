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
	"strings"
	"sync"
	"time"
)

// BuiltinWordlist is a compact but effective set of paths to probe when no
// external wordlist is provided via --wordlist.
var BuiltinWordlist = []string{
	// Admin / auth
	"admin", "admin/", "admin/login", "admin/dashboard", "admin/panel",
	"administrator", "administrator/", "login", "login.php", "login.html",
	"logout", "signup", "register", "dashboard", "panel", "cp", "backend",
	"console", "manage", "management", "control",
	// CMS / frameworks
	"wp-admin", "wp-admin/", "wp-login.php", "wp-config.php",
	"wp-content", "wp-includes", "xmlrpc.php", "wp-cron.php",
	"phpmyadmin", "phpmyadmin/", "myadmin", "phpMyAdmin",
	"joomla", "drupal", "magento", "prestashop",
	// API
	"api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/", "api/v3",
	"api/admin", "api/user", "api/users", "api/auth", "api/login",
	"v1", "v2", "v3", "graphql", "graphiql", "rest", "rpc",
	// Docs / spec
	"swagger", "swagger-ui", "swagger-ui/", "swagger.json", "swagger.yaml",
	"openapi.json", "openapi.yaml", "api-docs", "api-docs/",
	// Spring Boot actuator
	"actuator", "actuator/", "actuator/health", "actuator/env",
	"actuator/mappings", "actuator/beans", "actuator/info",
	"actuator/metrics", "actuator/logfile", "actuator/httptrace",
	// Health / status
	"health", "healthz", "health/", "status", "ping", "version",
	"info", "metrics", "debug", "trace", "ready", "readyz",
	// Files / uploads
	"upload", "uploads", "uploads/", "files", "files/", "media",
	"media/", "static", "assets", "assets/", "public", "public/",
	"download", "downloads", "images", "img", "js", "css",
	// core.Config / secrets
	".env", ".env.local", ".env.production", ".env.development",
	".env.example", ".env.backup",
	"config", "config.php", "config.yml", "config.yaml", "config.json",
	"configuration", "settings", "settings.php",
	"secrets", "secret", "keys", "key", "credentials",
	// VCS / project files
	".git/HEAD", ".git/config", ".gitignore", ".gitmodules",
	".svn/entries", ".hg/hgrc",
	"Dockerfile", ".dockerenv", ".docker-compose.yml",
	"docker-compose.yml", "docker-compose.yaml",
	".travis.yml", ".circleci/config.yml", ".github",
	"Makefile", "composer.json", "package.json", "package-lock.json",
	"yarn.lock", "Gemfile", "requirements.txt", "go.mod",
	// Backup / dumps
	"backup", "backup.zip", "backup.tar.gz", "backup.sql",
	"dump.sql", "db.sql", "database.sql", "data.sql", "old",
	"archive", "bak", "*.bak",
	// PHP backdoors / shells
	"shell.php", "cmd.php", "webshell.php", "c99.php", "r57.php",
	"b374k.php", "mini.php", "test.php", "info.php", "phpinfo.php",
	// Server / infra
	"server-status", "server-info", ".htaccess", ".htpasswd",
	"web.config", "Web.config", "nginx.conf", "apache2.conf",
	"cgi-bin", "cgi-bin/", "bin",
	// Well-known
	"robots.txt", "sitemap.xml", "sitemap.xml.gz",
	".well-known/", ".well-known/security.txt",
	"crossdomain.xml", "clientaccesspolicy.xml",
	"favicon.ico", "apple-touch-icon.png",
	// Auth / SSO
	"auth", "oauth", "oauth2", "saml", "sso", "cas",
	"token", "tokens", "session", "sessions",
	// Staging / dev leftovers
	"test", "tests", "dev", "development", "staging", "uat",
	"demo", "sandbox", "tmp", "temp", "cache", "logs", "log",
	// Misc
	"install.php", "setup.php", "install.sql", "setup",
	"user", "users", "account", "accounts", "members", "member",
	"profile", "internal", "private", "error", "500", "404",
	"README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md",
}

// DirScanResult holds the outcome of a single path probe.
type DirScanResult struct {
	URL           string
	Status        int
	ContentLength int
	ContentType   string
}

// ScanDirs performs concurrent directory brute-force against target.
// It returns core.ScanResult entries ready to merge into the main report.
func ScanDirs(client *http.Client, cfg *core.Config, target string) []core.ScanResult {
	wordlist, err := loadWordlist(cfg.Wordlist)
	if err != nil {
		output.Error("Cannot load wordlist %q: %v — falling back to built-in \n", cfg.Wordlist, err)
		wordlist = BuiltinWordlist
	}

	base, err := url.Parse(target)
	if err != nil {
		return nil
	}
	// Strip any existing path so we always scan from root
	base.Path = "/"
	base.RawQuery = ""
	base.Fragment = ""
	baseStr := strings.TrimRight(base.String(), "/")

	output.Info("[*] DirScan     : %s (%d paths, %d workers)\n", baseStr, len(wordlist), cfg.Threads)

	// Establish a baseline using a random non-existent path so we can filter
	// out SPA catch-all 200s and WAF blanket 403s that return the same status
	// and similar body length for every path.
	randPath := fmt.Sprintf("/sxsc-dirscan-baseline-%d", rand.Int63n(9999999))
	baseStatus, baseLen, _ := dirProbe(client, cfg, baseStr+randPath)

	type job struct{ path string }
	jobs := make(chan job, len(wordlist))
	for _, p := range wordlist {
		jobs <- job{path: strings.TrimLeft(p, "/")}
	}
	close(jobs)

	var (
		mu      sync.Mutex
		hits    []DirScanResult
		wg      sync.WaitGroup
		workers = cfg.Threads
	)
	if workers <= 0 {
		workers = 10
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if cfg.Limiter != nil {
					cfg.Limiter.Wait()
				}
				probeURL := baseStr + "/" + j.path
				status, cLen, cType := dirProbe(client, cfg, probeURL)

				if status == 0 || status == 404 {
					continue
				}
				// Filter SPA catch-all 200s and WAF blanket blocks:
				// if the baseline (random nonexistent path) returned the same
				// status AND similar body length, this path is likely a false hit.
				if status == baseStatus && absInt(cLen-baseLen) < 100 {
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
			}
		}()
	}
	wg.Wait()

	// Convert DirScanResult → core.ScanResult
	var results []core.ScanResult
	for _, h := range hits {
		sev := dirSeverity(h.Status, h.URL)
		results = append(results, core.ScanResult{
			Type:      "Directory / File Found",
			URL:       h.URL,
			Method:    "GET",
			Parameter: "-",
			Payload:   "-",
			Severity:  sev,
			Evidence: fmt.Sprintf("HTTP %d | %d bytes | %s",
				h.Status, h.ContentLength, h.ContentType),
			Timestamp: time.Now(),
		})
	}

	output.Info("[*] DirScan     : %d path(s) found\n", len(hits))
	return results
}

// dirProbe sends a HEAD (falling back to GET) to url and returns
// status code, content-length, and content-type.
func dirProbe(client *http.Client, cfg *core.Config, rawURL string) (int, int, string) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return 0, 0, ""
	}
	core.ApplyHeaders(req, cfg)
	// Tight timeout for dir-scan probes to keep throughput high
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, ""
	}
	defer resp.Body.Close()
	// Drain a small amount to get accurate content-type
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	_ = n

	cl := int(resp.ContentLength)
	ct := resp.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i != -1 {
		ct = strings.TrimSpace(ct[:i])
	}
	return resp.StatusCode, cl, ct
}

// dirSeverity assigns a severity to a found path based on its status code
// and whether it looks sensitive.
func dirSeverity(status int, rawURL string) string {
	pathLow := strings.ToLower(rawURL)
	// Sensitive patterns always HIGH regardless of status
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
		return "LOW" // resource exists but access denied
	default:
		return "INFO"
	}
}

// statusLabel returns a coloured ANSI prefix for a status code.
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

// absInt returns the absolute value of x.
func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// loadWordlist reads a wordlist file (one path per line, # comments ignored).
// Returns BuiltinWordlist if path is empty.
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
