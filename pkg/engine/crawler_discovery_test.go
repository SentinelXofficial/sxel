package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestCrawlDiscoverySources(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><a href="/home">home</a></html>`)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html>home</html>`)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin\nDisallow: /hidden/api\nAllow: /public\nSitemap: http://"+r.Host+"/sitemap.xml\n")
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>admin</html>")
	})
	mux.HandleFunc("/hidden/api", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>api</html>")
	})
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>public</html>")
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>http://`+r.Host+`/sitemap2.xml</loc></sitemap><url><loc>http://`+r.Host+`/fromsitemap</loc></url></urlset>`)
	})
	mux.HandleFunc("/sitemap2.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://`+r.Host+`/nested</loc></url></urlset>`)
	})
	mux.HandleFunc("/fromsitemap", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>sitemap</html>")
	})
	mux.HandleFunc("/nested", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>nested</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &core.Config{Threads: 4}
	c := NewCrawler(srv.Client(), cfg)
	res := c.Crawl(srv.URL + "/")
	got := map[string]bool{}
	for _, r := range res {
		got[r.URL] = true
	}
	for _, want := range []string{
		srv.URL + "/admin",
		srv.URL + "/hidden/api",
		srv.URL + "/public",
		srv.URL + "/fromsitemap",
		srv.URL + "/nested",
	} {
		if !got[want] {
			t.Errorf("missing discovered URL %s (got %v)", want, got)
		}
	}
	if got[srv.URL+"/robots.txt"] {
		t.Errorf("robots.txt itself must not be queued")
	}
	if got[srv.URL+"/sitemap.xml"] || got[srv.URL+"/sitemap2.xml"] {
		t.Errorf("sitemap files themselves must not be queued")
	}
}

func TestExtractLinksBaseAndRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	body := `<html><base href="` + srv.URL + `/sub/"><a href="rel.html">r</a><meta http-equiv="refresh" content="0;url=/fresh">`
	c := NewCrawler(srv.Client(), &core.Config{})
	pu, _ := url.Parse(srv.URL)
	c.baseHost = pu.Host
	links := c.extractLinks(body, srv.URL+"/deep/page.html")
	found := map[string]bool{}
	for _, l := range links {
		found[l] = true
	}
	if !found[srv.URL+"/sub/rel.html"] {
		t.Errorf("base tag not honored: %v", found)
	}
	if !found[srv.URL+"/fresh"] {
		t.Errorf("meta refresh not followed: %v", found)
	}
}

func TestParseRobotsSkippedNoise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL)
	c := NewCrawler(srv.Client(), &core.Config{})
	seeds := c.parseRobots("Disallow: /ok\nDisallow: /\nDisallow: /*.php\nAllow: /x\n", base)
	if len(seeds) != 2 {
		t.Errorf("expected 2 path seeds, got %v", seeds)
	}
	for _, s := range seeds {
		if !strings.HasPrefix(s, srv.URL) {
			t.Errorf("seed not resolved against origin: %s", s)
		}
	}
}
