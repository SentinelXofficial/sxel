package engine

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestCrawlIndexFallback(t *testing.T) {
	var mu sync.Mutex
	hit := map[string]int{}
	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.WriteHeader(404)
			w.Write([]byte("nope"))
		case "/index.html":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<a href="/page2">p2</a>`))
		case "/page2":
			w.Write([]byte(`<a href="/">home</a>`))
		default:
			w.WriteHeader(404)
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
	if !got[ext.URL+"/index.html"] {
		t.Errorf("expected /index.html crawled, got %v", got)
	}
	if !got[ext.URL+"/page2"] {
		t.Errorf("expected /page2 crawled via fallback, got %v", got)
	}
}

func TestCrawlIndexFallbackMultiSeed(t *testing.T) {
	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(404)
		case "/index.html", "/admin", "/search":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<a href="/x">x</a>`))
		case "/x":
			w.Write([]byte(`<a href="/">home</a>`))
		default:
			w.WriteHeader(404)
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
	for _, want := range []string{"/index.html", "/admin", "/search", "/x"} {
		if !got[ext.URL+want] {
			t.Errorf("expected %s crawled from fallback seeds, got %v", want, got)
		}
	}
}

func TestCrawlNoFallbackWhenRootOK(t *testing.T) {
	var mu sync.Mutex
	hit := map[string]int{}
	ext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<a href="/p">p</a>`))
		case "/p":
			w.Write([]byte(`<a href="/">home</a>`))
		default:
			w.WriteHeader(404)
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
	if !got[ext.URL+"/"] || !got[ext.URL+"/p"] {
		t.Errorf("expected root crawl, got %v", got)
	}
	if hit["/index.html"] != 0 {
		t.Errorf("fallback candidates should not be probed when root is OK, hit=%v", hit)
	}
}
