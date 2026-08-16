package engine

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestCanonicalURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://Example.COM:80/About/", "http://example.com/About"},
		{"https://example.com:443/x?a=1", "https://example.com/x?a=1"},
		{"http://example.com/page#frag", "http://example.com/page"},
		{"http://example.com/page/#frag", "http://example.com/page"},
		{"http://example.com/", "http://example.com/"},
		{"http://example.com/a/b/c/", "http://example.com/a/b/c"},
		{"http://example.com/s?q=x", "http://example.com/s?q=x"},
	}
	for _, c := range cases {
		if got := CanonicalURL(c.in); got != c.want {
			t.Errorf("CanonicalURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCrawlDedupAndFilters(t *testing.T) {
	var mu sync.Mutex
	hit := map[string]int{}

	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body>
				<a href="/page1">p1</a>
				<a href="/page1/">p1 dup</a>
				<a href="/page1#frag">p1 dup2</a>
				<a href="/img.png">img</a>
				<a href="/assets/app.css">css</a>
				<a href="/docs/manual.pdf">pdf</a>
				<a href="http://evil.example/steal">out of scope</a>
				<iframe src="/iframe-page"></iframe>
				<a href="/frameset">frames</a>
				<area href="/area-page" />
			</body></html>`))
		case "/frameset":
			w.Write([]byte(`<html><frameset cols="50%,50%"><frame src="/frame-page"></frameset></html>`))
		case "/page1", "/page1/", "/page1#frag":
			w.Write([]byte(`<a href="/page2">next</a>`))
		case "/page2":
			w.Write([]byte(`<a href="/">home</a>`))
		default:
			w.WriteHeader(200)
			w.Write([]byte("plain"))
		}
	}))
	defer ext.Close()

	cfg := &core.Config{Threads: 4}
	c := NewCrawler(ext.Client(), cfg)
	results := c.Crawl(ext.URL + "/")

	got := map[string]bool{}
	for _, r := range results {
		got[r.URL] = true
	}

	want := map[string]bool{
		ext.URL + "/":            true,
		ext.URL + "/page1":       true,
		ext.URL + "/page2":       true,
		ext.URL + "/iframe-page": true,
		ext.URL + "/frame-page":  true,
		ext.URL + "/area-page":   true,
	}
	for u := range want {
		if !got[u] {
			t.Errorf("expected crawled page %q, got %v", u, got)
		}
	}
	for _, skip := range []string{"/img.png", "/assets/app.css", "/docs/manual.pdf", "/page1/", "/page1#frag"} {
		if got[ext.URL+skip] {
			t.Errorf("should NOT have crawled %q", skip)
		}
	}
	if hit["/page1"] != 1 {
		t.Errorf("dedup failed: /page1 hit %d times, want 1", hit["/page1"])
	}
	if hit["/"] != 2 {
		t.Errorf("home hit %d times, want 2 (1 fallback probe + 1 crawl, no cycle re-crawl)", hit["/"])
	}
}

func TestCrawlKeepsDistinctQueries(t *testing.T) {
	var mu sync.Mutex
	hit := map[string]int{}

	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit[r.URL.RequestURI()]++
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Write([]byte(`<a href="/s?q=a">a</a><a href="/s?q=b">b</a>`))
		} else {
			w.Write([]byte("ok"))
		}
	}))
	defer ext.Close()

	cfg := &core.Config{Threads: 4}
	c := NewCrawler(ext.Client(), cfg)
	results := c.Crawl(ext.URL + "/")

	if hit["/s?q=a"] != 1 || hit["/s?q=b"] != 1 {
		t.Errorf("query variants should be distinct pages: %v", hit)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 results (/, /s?q=a, /s?q=b), got %d", len(results))
	}
}

func TestCrawlSkipsErrorsAndMaxPages(t *testing.T) {
	var mu sync.Mutex
	hit := map[string]int{}

	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<a href="/broken">b</a><a href="/ok1">o1</a><a href="/ok2">o2</a><a href="/ok3">o3</a>`))
		case "/broken":
			w.WriteHeader(500)
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer ext.Close()

	cfg := &core.Config{Threads: 4, MaxPages: 3}
	c := NewCrawler(ext.Client(), cfg)
	results := c.Crawl(ext.URL + "/")

	if hit["/broken"] != 1 {
		t.Errorf("500 page: exactly 1 discovery request expected (skipped from scan), hit map: %v", hit)
	}
	if len(results) > 3 {
		t.Errorf("MaxPages=3 violated: got %d results (%v)", len(results), hit)
	}
	if hit["/ok2"] != 0 || hit["/ok3"] != 0 {
		t.Errorf("MaxPages budget should have skipped /ok2 and /ok3, hit map: %v", hit)
	}
}
