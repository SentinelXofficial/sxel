package engine

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type Fingerprint struct {
	Tech      []string
	Server    string
	PoweredBy string
	IsAPI     bool
	IsSPA     bool
	HasLogin  bool
	HasSearch bool
	Endpoints []string
}

type techPattern struct {
	re    *regexp.Regexp
	techs []string
}

var techFingerprints = []techPattern{
	{regexp.MustCompile(`wp-content`), []string{"WordPress"}},
	{regexp.MustCompile(`wp-includes`), []string{"WordPress"}},
	{regexp.MustCompile(`/wp-json`), []string{"WordPress"}},
	{regexp.MustCompile(`<meta name="generator" content="WordPress`), []string{"WordPress"}},
	{regexp.MustCompile(`Drupal`), []string{"Drupal"}},
	{regexp.MustCompile(`Joomla`), []string{"Joomla"}},
	{regexp.MustCompile(`Magento`), []string{"Magento"}},
	{regexp.MustCompile(`react\.(production|development)\.min`), []string{"React"}},
	{regexp.MustCompile(`vue\.(runtime|production)\.`), []string{"Vue.js"}},
	{regexp.MustCompile(`angular\.module`), []string{"Angular"}},
	{regexp.MustCompile(`__NEXT_DATA__`), []string{"Next.js"}},
	{regexp.MustCompile(`_next/static`), []string{"Next.js"}},
	{regexp.MustCompile(`<div id="__next"`), []string{"Next.js"}},
	{regexp.MustCompile(`laravel`), []string{"Laravel"}},
	{regexp.MustCompile(`csrf-token`), []string{"Laravel"}},
	{regexp.MustCompile(`Django`), []string{"Django"}},
	{regexp.MustCompile(`rails`), []string{"Ruby on Rails"}},
	{regexp.MustCompile(`spring`), []string{"Spring Boot"}},
	{regexp.MustCompile(`actuator`), []string{"Spring Boot"}},
}

var serverTech = map[string]string{
	"nginx":      "Nginx",
	"apache":     "Apache",
	"iis":        "IIS",
	"cloudflare": "Cloudflare",
	"varnish":    "Varnish",
	"express":    "Express.js",
	"gunicorn":   "Gunicorn",
	"tomcat":     "Tomcat",
	"jetty":      "Jetty",
	"caddy":      "Caddy",
	"litespeed":  "LiteSpeed",
}

var apiPattern = regexp.MustCompile(`/(api|v[0-9]+|graphql|rest|rpc|query)(/|$)`)

var numParam = regexp.MustCompile(`/\d{1,12}(/|$)`)

func FingerprintTarget(body string, headers map[string]string, targetURL string) Fingerprint {
	fp := Fingerprint{}

	if srv, ok := headers["Server"]; ok {
		fp.Server = srv
		for keyword, tech := range serverTech {
			if strings.Contains(strings.ToLower(srv), keyword) {
				fp.Tech = append(fp.Tech, tech)
			}
		}
	}

	if xpb, ok := headers["X-Powered-By"]; ok {
		fp.PoweredBy = xpb
		fp.Tech = append(fp.Tech, xpb)
	}

	bodyLow := strings.ToLower(body)
	for _, p := range techFingerprints {
		if p.re.MatchString(bodyLow) {
			fp.Tech = append(fp.Tech, p.techs...)
		}
	}

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

	if apiPattern.MatchString(targetURL) || strings.Contains(bodyLow, `"application/json"`) {
		fp.IsAPI = true
	}
	if strings.Contains(bodyLow, "<div id=\"root\">") ||
		strings.Contains(bodyLow, "<div id=\"app\">") ||
		strings.Contains(bodyLow, "window.__") {
		fp.IsSPA = true
	}

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
		return true
	}
}

func NormalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := numParam.ReplaceAllString(u.Path, "/{id}$1")
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
