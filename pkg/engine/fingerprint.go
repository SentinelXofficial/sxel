package engine

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Fingerprint holds detected technology and endpoint info about a target.
type Fingerprint struct {
	Tech       []string // detected technologies (WordPress, React, PHP, etc.)
	Server     string   // Server header value
	PoweredBy  string   // X-Powered-By header value
	IsAPI      bool     // REST/JSON API
	IsSPA      bool     // Single Page Application
	HasLogin   bool     // Has login form
	HasSearch  bool     // Has search endpoint
	Endpoints  []string // unique endpoint patterns discovered
}

// techFingerprints maps response body/header patterns to technology names.
var techFingerprints = map[string][]string{
	`wp-content`:                  {"WordPress"},
	`wp-includes`:                 {"WordPress"},
	`/wp-json`:                    {"WordPress"},
	`<meta name="generator" content="WordPress`: {"WordPress"},
	`Drupal`:                      {"Drupal"},
	`Joomla`:                      {"Joomla"},
	`Magento`:                     {"Magento"},
	`react\.(production|development)\.min`: {"React"},
	`vue\.(runtime|production)\.`: {"Vue.js"},
	`angular\.module`:             {"Angular"},
	`__NEXT_DATA__`:               {"Next.js"},
	`_next/static`:                {"Next.js"},
	`<div id="__next"`:            {"Next.js"},
	`laravel`:                     {"Laravel"},
	`csrf-token`:                  {"Laravel"},
	`Django`:                      {"Django"},
	`rails`:                       {"Ruby on Rails"},
	`spring`:                      {"Spring Boot"},
	`actuator`:                    {"Spring Boot"},
	`PHPSESSID`:                   {"PHP"},
	`ASP.NET_SessionId`:           {"ASP.NET"},
	`JSESSIONID`:                  {"Java"},
	`X-Drupal`:                    {"Drupal"},
}

// serverTech maps Server header values to tech names.
var serverTech = map[string]string{
	"nginx":     "Nginx",
	"apache":    "Apache",
	"iis":       "IIS",
	"cloudflare": "Cloudflare",
	"varnish":   "Varnish",
	"express":   "Express.js",
	"gunicorn":  "Gunicorn",
	"tomcat":    "Tomcat",
	"jetty":     "Jetty",
	"caddy":     "Caddy",
	"liteSpeed": "LiteSpeed",
}

// apiPattern matches REST API-style URL paths.
var apiPattern = regexp.MustCompile(`/(api|v[0-9]+|graphql|rest|rpc|query)(/|$)`)

// numParam matches URL path segments that look like numeric IDs.
var numParam = regexp.MustCompile(`/\d{1,12}(/|$)`)

// FingerprintTarget probes a URL and returns its technology fingerprint.
func FingerprintTarget(body string, headers map[string]string, targetURL string) Fingerprint {
	fp := Fingerprint{}

	// ── Server header ─────────────────────────────────────────────────────
	if srv, ok := headers["Server"]; ok {
		fp.Server = srv
		for keyword, tech := range serverTech {
			if strings.Contains(strings.ToLower(srv), keyword) {
				fp.Tech = append(fp.Tech, tech)
			}
		}
	}

	// ── X-Powered-By ──────────────────────────────────────────────────────
	if xpb, ok := headers["X-Powered-By"]; ok {
		fp.PoweredBy = xpb
		fp.Tech = append(fp.Tech, xpb)
	}

	// ── Body pattern matching ─────────────────────────────────────────────
	bodyLow := strings.ToLower(body)
	for pattern, techs := range techFingerprints {
		if strings.Contains(bodyLow, strings.ToLower(pattern)) {
			for _, t := range techs {
				fp.Tech = append(fp.Tech, t)
			}
		}
	}

	// ── Set-Cookie based detection ────────────────────────────────────────
	if ck, ok := headers["Set-Cookie"]; ok {
		ckLow := strings.ToLower(ck)
		if strings.Contains(ckLow, "phpsessid") {
			fp.Tech = append(fp.Tech, "PHP")
		}
		if strings.Contains(ckLow, "jsessionid") {
			fp.Tech = append(fp.Tech, "Java")
		}
		if strings.Contains(ckLow, "asp.net") {
			fp.Tech = append(fp.Tech, "ASP.NET")
		}
	}

	// ── API / SPA detection ───────────────────────────────────────────────
	if apiPattern.MatchString(targetURL) || strings.Contains(bodyLow, `"application/json"`) {
		fp.IsAPI = true
	}
	if strings.Contains(bodyLow, "<div id=\"root\">") ||
		strings.Contains(bodyLow, "<div id=\"app\">") ||
		strings.Contains(bodyLow, "window.__") {
		fp.IsSPA = true
	}

	// ── Login / Search detection ──────────────────────────────────────────
	if strings.Contains(bodyLow, `<input type="password"`) ||
		strings.Contains(bodyLow, `name="password"`) ||
		strings.Contains(bodyLow, `name="passwd"`) {
		fp.HasLogin = true
	}
	if strings.Contains(bodyLow, `<input type="search"`) ||
		strings.Contains(bodyLow, `name="q"`) ||
		strings.Contains(bodyLow, `name="query"`) ||
		strings.Contains(bodyLow, `name="search"`) {
		fp.HasSearch = true
	}

	fp.Tech = dedupStrings(fp.Tech)
	return fp
}

// ShouldScan returns true if a module should run against a given target based on fingerprinting.
func ShouldScan(module string, fp Fingerprint) bool {
	switch module {
	case "sqli", "nosql", "cmdi", "ssti":
		return fp.HasSearch || fp.IsAPI || fp.HasLogin
	case "jwt", "idor", "graphql":
		return fp.IsAPI
	case "xss", "csrf":
		return fp.HasLogin || fp.HasSearch
	case "fileupload":
		return fp.HasLogin
	case "ssrf", "xxe", "lfi":
		return fp.IsAPI || fp.HasSearch
	default:
		return true // scan everything
	}
}

// NormalizeURL strips numeric IDs and query params to produce endpoint pattern.
func NormalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := numParam.ReplaceAllString(u.Path, "/{id}")
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, path)
}

func dedupStrings(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
