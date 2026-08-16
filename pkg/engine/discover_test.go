package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestParseSitemapHostScope(t *testing.T) {
	var mu sync.Mutex
	reqLog := map[string]int{}

	base := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqLog[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/sitemap.xml":
			fmt.Fprintf(w, `<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
				<sitemap><loc>http://%s/nested.xml</loc></sitemap>
				<sitemap><loc>http://foreign.example.test/nested2.xml</loc></sitemap>
			</sitemapindex>`, r.Host)
		case "/nested.xml":
			fmt.Fprintf(w, `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
				<url><loc>http://%s/same1</loc></url>
				<url><loc>http://%s/same2</loc></url>
				<url><loc>http://sub.other.test/s</loc></url>
				<url><loc>https://attacker.example/example.test/x</loc></url>
			</urlset>`, r.Host, r.Host)
		default:
			w.WriteHeader(404)
		}
	}))
	defer base.Close()

	cfg := &core.Config{}
	urls := ParseSitemap(base.Client(), cfg, base.URL+"/")

	has := func(u string) bool {
		for _, x := range urls {
			if x == u {
				return true
			}
		}
		return false
	}

	for _, want := range []string{base.URL + "/same1", base.URL + "/same2"} {
		if !has(want) {
			t.Errorf("expected same-site sitemap URL %q in %v", want, urls)
		}
	}
	for _, bad := range []string{
		"http://sub.other.test/s",
		"https://attacker.example/example.test/x",
	} {
		if has(bad) {
			t.Errorf("out-of-scope URL %q leaked into seeds: %v", bad, urls)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if reqLog["/nested2.xml"] != 0 {
		t.Errorf("foreign-domain nested sitemap must not be fetched, request log: %v", reqLog)
	}
}

func TestParseRobotsTxtHostScope(t *testing.T) {
	base := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `User-agent: *
Disallow: /admin
Disallow: /private/
Sitemap: http://%s/base-sitemap.xml
Sitemap: http://external.example/sitemap.xml
Sitemap: http://sub.example.test/sitemap.xml`, r.Host)
	}))
	defer base.Close()

	cfg := &core.Config{}
	paths := ParseRobotsTxt(base.Client(), cfg, base.URL+"/")

	has := func(u string) bool {
		for _, x := range paths {
			if x == u {
				return true
			}
		}
		return false
	}
	for _, want := range []string{base.URL + "/admin", base.URL + "/private/", base.URL + "/base-sitemap.xml"} {
		if !has(want) {
			t.Errorf("expected %q in %v", want, paths)
		}
	}
	for _, bad := range []string{
		"http://external.example/sitemap.xml",
		"http://sub.example.test/sitemap.xml",
	} {
		if has(bad) {
			t.Errorf("out-of-scope robots URL %q leaked: %v", bad, paths)
		}
	}
}
