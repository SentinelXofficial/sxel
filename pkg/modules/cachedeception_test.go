package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestScanCacheDeceptionDetectsDeceit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/profile" {
			w.Header().Set("X-Cache", "MISS")
			w.Write([]byte("private user data: alice@example.com session=abc123"))
			return
		}
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("X-Cache", "HIT")
			w.Write([]byte("private user data: alice@example.com session=abc123"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test"}
	findings := ScanCacheDeception(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/profile"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 cache deception finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Type, "Cache Deception") {
		t.Errorf("expected Cache Deception type, got %q", findings[0].Type)
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("expected HIGH severity with cache header, got %q", findings[0].Severity)
	}
}

func TestScanCacheDeceptionNoFPOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/profile" {
			w.Write([]byte("private user data"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test"}
	findings := ScanCacheDeception(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/profile"})
	if len(findings) != 0 {
		t.Fatalf("clean stack must not produce cache deception findings, got %+v", findings)
	}
}
