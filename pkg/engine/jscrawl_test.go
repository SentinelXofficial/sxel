package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestJSRenderWithoutChrome(t *testing.T) {
	cfg := &core.Config{UserAgent: "sxel-test"}
	c := NewCrawler(http.DefaultClient, cfg)
	links, forms := c.jsRender("http://example.invalid/")
	if links != nil || forms != nil {
		t.Fatalf("expected nil results without chrome, got %v %v", links, forms)
	}
}

func TestJSRenderDiscoversJSGeneratedContent(t *testing.T) {
	if core.ChromePath() == "" {
		t.Skip("chrome not available")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/js-only" {
			io.WriteString(w, "js page")
			return
		}
		io.WriteString(w, `<html><head></head><body>
			<script>document.write('<a href="/js-only">js link</a>');</script>
			<script>document.getElementById("app").innerHTML='<form action="/js-form"><input name="q"></form>';</script>
			<div id="app"></div>
		</body></html>`)
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	c := NewCrawler(http.DefaultClient, cfg)
	links, forms := c.jsRender(srv.URL + "/")
	found := false
	for _, l := range links {
		if strings.Contains(l, "/js-only") {
			found = true
		}
	}
	if !found {
		t.Fatalf("JS-generated link not discovered: %v", links)
	}
	hasForm := false
	for _, f := range forms {
		if strings.Contains(f.Action, "/js-form") {
			hasForm = true
		}
	}
	if !hasForm {
		t.Fatalf("JS-generated form not discovered: %+v", forms)
	}
}

func TestFetchPageJSCrawlFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<a href="/static">static</a>`)
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	c := NewCrawler(http.DefaultClient, cfg)
	links, forms, err := c.fetchPage(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) == 0 {
		t.Fatal("static link not found")
	}
	_ = forms
}
