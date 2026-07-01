package engine

import (
	"github.com/SentinelXofficial/sxel/pkg/core"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ParseRobotsTxt fetches robots.txt and extracts all paths
func ParseRobotsTxt(client *http.Client, cfg *core.Config, baseURL string) []string {
	p, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", p.Scheme, p.Host)
	body, _, err := core.DoGET(client, cfg, robotsURL)
	if err != nil {
		return nil
	}
	base, _ := url.Parse(baseURL)
	seen := map[string]bool{}
	var paths []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "disallow:") || strings.HasPrefix(lower, "allow:") || strings.HasPrefix(lower, "sitemap:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			path := strings.TrimSpace(parts[1])
			if path == "" || path == "/" || strings.Contains(path, "*") {
				continue
			}
			var full string
			if strings.HasPrefix(path, "http") {
				full = path
			} else {
				if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
				full = fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, path)
			}
			if !seen[full] {
				seen[full] = true
				paths = append(paths, full)
			}
		}
	}
	if len(paths) > 0 {
		fmt.Printf("  [robots.txt] %d paths found\n", len(paths))
	}
	return paths
}

// ParseSitemap fetches sitemap.xml and extracts URLs
func ParseSitemap(client *http.Client, cfg *core.Config, baseURL string) []string {
	p, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	sitemapURL := fmt.Sprintf("%s://%s/sitemap.xml", p.Scheme, p.Host)
	body, _, err := core.DoGET(client, cfg, sitemapURL)
	if err != nil {
		return nil
	}
	type URLSet struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
		Sitemaps []struct {
			Loc string `xml:"loc"`
		} `xml:"sitemap"`
	}
	var us URLSet
	xml.Unmarshal([]byte(body), &us) //nolint:errcheck
	base, _ := url.Parse(baseURL)
	seen := map[string]bool{}
	var urls []string
	for _, u := range us.URLs {
		if strings.Contains(u.Loc, base.Host) && !seen[u.Loc] {
			seen[u.Loc] = true
			urls = append(urls, u.Loc)
		}
	}
	// Follow nested sitemap index entries (common on large sites that split sitemaps)
	for _, sm := range us.Sitemaps {
		if sm.Loc == "" {
			continue
		}
		nestedBody, _, err := core.DoGET(client, cfg, sm.Loc)
		if err != nil {
			continue
		}
		var nestedUS URLSet
		xml.Unmarshal([]byte(nestedBody), &nestedUS) //nolint:errcheck
		for _, u := range nestedUS.URLs {
			if strings.Contains(u.Loc, base.Host) && !seen[u.Loc] {
				seen[u.Loc] = true
				urls = append(urls, u.Loc)
			}
		}
	}
	if len(urls) > 0 {
		fmt.Printf("  [sitemap.xml] %d URLs found\n", len(urls))
	}
	return urls
}

var jsEndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["'](/api/[^"'\s\)]+)["']`),
	regexp.MustCompile(`["'](/v[0-9]+/[^"'\s\)]+)["']`),
	regexp.MustCompile(`fetch\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`axios\.\w+\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`\$\.(?:get|post|ajax)\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`["'](https?://[^"'\s]+\?[^"'\s]+)["']`),
	regexp.MustCompile(`url\s*[:=]\s*["']([^"']+)["']`),
	regexp.MustCompile(`href\s*=\s*["']([^"'#][^"']*\?[^"']+)["']`),
	regexp.MustCompile(`action\s*=\s*["']([^"']+)["']`),
}

// ExtractJSEndpoints finds API endpoints in inline JS and external JS files
func ExtractJSEndpoints(client *http.Client, cfg *core.Config, pageURL string) []string {
	body, _, err := core.DoGET(client, cfg, pageURL)
	if err != nil {
		return nil
	}
	p, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	base, _ := url.Parse(fmt.Sprintf("%s://%s", p.Scheme, p.Host))
	seen := map[string]bool{}
	var out []string

	extract := func(src string) {
		for _, re := range jsEndpointPatterns {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				if len(m) < 2 {
					continue
				}
				raw := m[1]
				var full string
				if strings.HasPrefix(raw, "http") {
					full = raw
				} else if strings.HasPrefix(raw, "/") {
					ref, err := url.Parse(raw)
					if err == nil {
						full = base.ResolveReference(ref).String()
					}
				}
				if full != "" && !seen[full] {
					seen[full] = true
					out = append(out, full)
				}
			}
		}
	}

	extract(body)

	// Also extract from external JS files
	jsFileRe := regexp.MustCompile(`src=["']([^"']+\.js(?:\?[^"']*)?)["']`)
	for _, m := range jsFileRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		jsURL := ResolveURL(base, m[1])
		if jsURL == "" {
			continue
		}
		jsBody, _, err := core.DoGET(client, cfg, jsURL)
		if err == nil {
			extract(jsBody)
		}
	}

	if len(out) > 0 {
		fmt.Printf("  [JS-endpoints] %d found at %s\n", len(out), pageURL)
	}
	return out
}

// ScanSensitiveFiles checks for commonly exposed sensitive paths
func ScanSensitiveFiles(client *http.Client, cfg *core.Config, baseURL string) []core.ScanResult {
	var results []core.ScanResult
	p, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	base := fmt.Sprintf("%s://%s", p.Scheme, p.Host)

	type file struct {
		path string
		sev  string
		desc string
	}
	files := []file{
		{"/.git/HEAD", "HIGH", "Git repository exposed"},
		{"/.git/config", "HIGH", "Git config exposed"},
		{"/.env", "HIGH", ".env file exposed (may contain secrets)"},
		{"/.env.local", "HIGH", ".env.local exposed"},
		{"/.env.production", "HIGH", ".env.production exposed"},
		{"/wp-config.php", "HIGH", "WordPress config exposed"},
		{"/config.php", "HIGH", "PHP config exposed"},
		{"/database.yml", "HIGH", "Rails database config exposed"},
		{"/config/database.yml", "HIGH", "Rails database config exposed"},
		{"/.htpasswd", "HIGH", "htpasswd exposed"},
		{"/backup.zip", "HIGH", "Backup archive exposed"},
		{"/backup.sql", "HIGH", "SQL dump exposed"},
		{"/dump.sql", "HIGH", "SQL dump exposed"},
		{"/web.config", "HIGH", "ASP.NET web.config exposed"},
		{"/appsettings.json", "HIGH", "ASP.NET appsettings exposed"},
		{"/application.properties", "HIGH", "Spring Boot config exposed"},
		{"/application.yml", "HIGH", "Spring Boot config exposed"},
		{"/actuator", "HIGH", "Spring Boot actuator exposed"},
		{"/actuator/env", "HIGH", "Spring Boot env endpoint"},
		{"/actuator/heapdump", "HIGH", "JVM heap dump endpoint"},
		{"/.aws/credentials", "HIGH", "AWS credentials exposed"},
		{"/phpinfo.php", "MEDIUM", "phpinfo() page exposed"},
		{"/info.php", "MEDIUM", "PHP info page exposed"},
		{"/server-status", "MEDIUM", "Apache server-status exposed"},
		{"/server-info", "MEDIUM", "Apache server-info exposed"},
		{"/_profiler", "MEDIUM", "Symfony profiler exposed"},
		{"/swagger.json", "MEDIUM", "Swagger API spec exposed"},
		{"/swagger-ui.html", "MEDIUM", "Swagger UI exposed"},
		{"/api/swagger.json", "MEDIUM", "API Swagger spec exposed"},
		{"/openapi.json", "MEDIUM", "OpenAPI spec exposed"},
		{"/graphql", "LOW", "GraphQL endpoint found"},
		{"/graphiql", "MEDIUM", "GraphiQL interface exposed"},
		{"/Dockerfile", "MEDIUM", "Dockerfile exposed"},
		{"/docker-compose.yml", "MEDIUM", "Docker Compose file exposed"},
		{"/docker-compose.yaml", "MEDIUM", "Docker Compose file exposed"},
		{"/.htaccess", "LOW", ".htaccess exposed"},
		{"/.DS_Store", "LOW", "macOS .DS_Store exposed"},
		{"/crossdomain.xml", "LOW", "Flash crossdomain policy"},
		{"/test.php", "LOW", "Test file exposed"},
		{"/admin", "LOW", "Admin panel path exists"},
		{"/admin.php", "LOW", "Admin PHP page exists"},
		{"/login", "INFO", "Login page found"},
		{"/robots.txt", "INFO", "robots.txt (informational)"},
		{"/sitemap.xml", "INFO", "sitemap.xml found"},
	}

	// Establish a baseline using a path that should never exist.
	// This lets us filter out SPA catch-all 200s and WAF blanket 403s.
	randPath := fmt.Sprintf("/sxsc-baseline-nonexistent-%d", time.Now().UnixNano()%9999999)
	var baselineStatus int
	var baselineLen int
	if req, err := http.NewRequest("GET", base+randPath, nil); err == nil {
		core.ApplyHeaders(req, cfg)
		if resp, err := client.Do(req); err == nil {
			b := core.ReadBody(resp.Body)
			resp.Body.Close()
			baselineStatus = resp.StatusCode
			baselineLen = len(b)
		}
	}
	absInt := func(x int) int {
		if x < 0 {
			return -x
		}
		return x
	}

	for _, f := range files {
		fullURL := base + f.path
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(req, cfg)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body := core.ReadBody(resp.Body)
		resp.Body.Close()
		bodyLen := len(body)

		// Compare against baseline to avoid mass false positives.
		exposed := false
		switch resp.StatusCode {
		case 200:
			// Only flag if baseline was not 200, or body length differs meaningfully
			// (a SPA returns identical-sized HTML for every path, real files differ)
			if baselineStatus != 200 || absInt(bodyLen-baselineLen) > 50 {
				exposed = true
			}
		case 403:
			// Only flag if baseline was not already 403 (WAF blanket block)
			if baselineStatus != 403 {
				exposed = true
			}
		}

		if exposed {
			results = append(results, core.ScanResult{
				Type: "Sensitive File/Endpoint Exposed", URL: fullURL,
				Method: "GET", Parameter: "path", Payload: f.path,
				Severity: f.sev,
				Evidence:  fmt.Sprintf("%s (HTTP %d)", f.desc, resp.StatusCode),
				Timestamp: time.Now(),
			})
			if f.sev == "HIGH" || f.sev == "MEDIUM" {
				fmt.Printf("  [SENSITIVE] %s HTTP=%d\n", f.path, resp.StatusCode)
			}
		}
	}
	return results
}
