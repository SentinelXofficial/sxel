package recon

import (
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var tagRe = regexp.MustCompile(`(?s)<[^>]+>`)
var spaceRe = regexp.MustCompile(`\s+`)

type TechRule struct {
	Name string
	Re   *regexp.Regexp
}

var techRules = []TechRule{
	{"nginx", regexp.MustCompile(`(?i)\bnginx(?:/[\d.]+)?`)},
	{"openresty", regexp.MustCompile(`(?i)openresty`)},
	{"apache", regexp.MustCompile(`(?i)\bapache(?:/[\d.]+)?`)},
	{"iis", regexp.MustCompile(`(?i)microsoft-iis`)},
	{"tomcat", regexp.MustCompile(`(?i)\btomcat`)},
	{"cloudflare", regexp.MustCompile(`(?i)cloudflare`)},
	{"varnish", regexp.MustCompile(`(?i)\bvarnish`)},
	{"akamai", regexp.MustCompile(`(?i)akamai`)},
	{"fastly", regexp.MustCompile(`(?i)fastly`)},
	{"wordpress", regexp.MustCompile(`(?i)wp-content|wp-includes|wp-json`)},
	{"drupal", regexp.MustCompile(`(?i)\bdrupal\b|x-generator:\s*drupal`)},
	{"joomla", regexp.MustCompile(`(?i)joomla`)},
	{"laravel", regexp.MustCompile(`(?i)laravel_session|__cookies=\s*laravel`)},
	{"symfony", regexp.MustCompile(`(?i)sf_redirect|symfony`)},
	{"rails", regexp.MustCompile(`(?i)\brails\b|authenticity_token`)},
	{"django", regexp.MustCompile(`(?i)django|csrftoken`)},
	{"flask", regexp.MustCompile(`(?i)\bflask\b`)},
	{"express", regexp.MustCompile(`(?i)x-powered-by:\s*express`)},
	{"next.js", regexp.MustCompile(`(?i)__next_data__|/_next/static/`)},
	{"nuxt.js", regexp.MustCompile(`(?i)__nuxt__`)},
	{"gatsby", regexp.MustCompile(`(?i)__gatsby|gatsby-`)},
	{"react", regexp.MustCompile(`(?i)data-reactroot|__react`)},
	{"vue.js", regexp.MustCompile(`(?i)data-server-rendered|__vue__|vue\.js`)},
	{"angular", regexp.MustCompile(`(?i)ng-version|ng-app`)},
	{"jquery", regexp.MustCompile(`(?i)\bjquery[\d.]*\.js`)},
	{"bootstrap", regexp.MustCompile(`(?i)bootstrap[^"]*\.(?:css|js)`)},
	{"php", regexp.MustCompile(`(?i)x-powered-by:\s*php|PHP/[\d.]+`)},
	{"asp.net", regexp.MustCompile(`(?i)x-aspnet-version|x-powered-by:\s*asp\.net|__requestverificationtoken`)},
	{"java", regexp.MustCompile(`(?i)jsessionid|javax\.faces|x-powered-by:\s*javaserver`)},
	{"go", regexp.MustCompile(`(?i)x-powered-by:\s*go|go-http-server`)},
	{"gitlab", regexp.MustCompile(`(?i)_gitlab_session`)},
	{"jenkins", regexp.MustCompile(`(?i)x-jenkins`)},
	{"grafana", regexp.MustCompile(`(?i)grafana_session`)},
	{"kibana", regexp.MustCompile(`(?i)kbn-name|kibana`)},
	{"shibboleth", regexp.MustCompile(`(?i)shibsession|_shibsession_`)},
	{"sap", regexp.MustCompile(`(?i)\bsap\b|sap-client`)},
}

func ProbeHost(client *http.Client, rawURL, ua string, favicon bool) (LiveHost, error) {
	var lh LiveHost
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return lh, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sxel-recon/1.0)")
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return lh, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	u, err := url.Parse(rawURL)
	if err != nil {
		return lh, err
	}
	lh.URL = rawURL
	lh.Host = u.Hostname()
	lh.Port = portOf(u)
	lh.Status = resp.StatusCode
	lh.Server = resp.Header.Get("Server")
	lh.Title = extractTitle(string(body))
	lh.Tech = detectTech(string(body), resp.Header)

	if favicon {
		lh.Favicon = FaviconHash(client, rawURL)
	}
	return lh, nil
}

func portOf(u *url.URL) int {
	p := u.Port()
	if p != "" {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		return n
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := tagRe.ReplaceAllString(m[1], " ")
	t = spaceRe.ReplaceAllString(t, " ")
	return html.UnescapeString(strings.TrimSpace(t))
}

func detectTech(body string, hdr http.Header) []string {
	var found []string
	hay := body + "\n"
	for k, vs := range hdr {
		for _, v := range vs {
			hay += k + ": " + v + "\n"
		}
	}
	for _, rule := range techRules {
		if rule.Re.MatchString(hay) {
			found = append(found, rule.Name)
		}
	}
	return found
}
