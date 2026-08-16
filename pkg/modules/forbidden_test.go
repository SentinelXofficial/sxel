package modules

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func Test403BypassHeaderTrick(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Original-URL") == "/admin" {
			io.WriteString(w, "admin panel content")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/sxel-nf-") {
			w.WriteHeader(404)
			io.WriteString(w, "not found")
			return
		}
		w.WriteHeader(403)
		io.WriteString(w, "forbidden")
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	target := core.CrawlResult{URL: srv.URL + "/admin"}
	res := Scan403Bypass(client, cfg, target)
	if len(res) == 0 {
		t.Fatal("header bypass not detected")
	}
	if res[0].Parameter != "header" || res[0].Severity != "MEDIUM" {
		t.Fatalf("finding metadata wrong: %+v", res[0])
	}
	if !strings.Contains(res[0].Evidence, "403 -> 200") {
		t.Fatalf("evidence wrong: %q", res[0].Evidence)
	}
}

func Test403BypassPathTrick(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sxel-nf-") {
			w.WriteHeader(404)
			io.WriteString(w, "not found")
			return
		}
		if strings.Contains(r.URL.Path, "%2f") || strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/admin/" {
			io.WriteString(w, "accidentally reachable")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/.") {
			io.WriteString(w, "trailing dot allowed")
			return
		}
		w.WriteHeader(403)
		io.WriteString(w, "forbidden")
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	target := core.CrawlResult{URL: srv.URL + "/admin"}
	res := Scan403Bypass(client, cfg, target)
	if len(res) == 0 {
		t.Fatal("path bypass not detected")
	}
}

func Test403BypassNoFPRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sxel-nf-") {
			w.WriteHeader(404)
			io.WriteString(w, "not found")
			return
		}
		if r.URL.Path != "/admin" {
			http.Redirect(w, r, "/public", http.StatusFound)
			return
		}
		w.WriteHeader(403)
		io.WriteString(w, "forbidden")
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	target := core.CrawlResult{URL: srv.URL + "/admin"}
	if res := Scan403Bypass(client, cfg, target); len(res) != 0 {
		t.Fatalf("3xx must not count as bypass: %+v", res)
	}
}

func Test403BypassNoFPRedirectToPublicPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sxel-nf-") {
			w.WriteHeader(404)
			io.WriteString(w, "not found")
			return
		}
		if r.URL.Path == "/admin" {
			http.Redirect(w, r, "/public", http.StatusFound)
			return
		}
		if r.URL.Path == "/public" {
			io.WriteString(w, "public login page")
			return
		}
		w.WriteHeader(403)
		io.WriteString(w, "forbidden")
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	target := core.CrawlResult{URL: srv.URL + "/admin"}
	if res := Scan403Bypass(client, cfg, target); len(res) != 0 {
		t.Fatalf("redirect to public page must not count as bypass: %+v", res)
	}
}

func Test403BypassSkipsNonForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "public page")
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	target := core.CrawlResult{URL: srv.URL + "/"}
	if res := Scan403Bypass(client, cfg, target); len(res) != 0 {
		t.Fatalf("public page should not trigger bypass scan: %+v", res)
	}
}
