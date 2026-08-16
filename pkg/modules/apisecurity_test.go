package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestScanAPISecuritySpecExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"openapi":"3.0.0","paths":{"/admin/users":{"get":{}},"/public/health":{"get":{}}}}`))
			return
		}
		if r.URL.Path == "/admin/users" {
			w.WriteHeader(200)
			w.Write([]byte(`[{"id":1,"email":"root@corp.local"}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test"}
	findings := ScanAPISecurity(srv.Client(), cfg, core.CrawlResult{URL: srv.URL})
	if len(findings) < 2 {
		t.Fatalf("expected spec exposure + auth bypass findings, got %+v", findings)
	}
	hasSpec, hasBypass := false, false
	for _, f := range findings {
		if strings.Contains(f.Type, "Specification Exposed") {
			hasSpec = true
		}
		if strings.Contains(f.Type, "Without Authentication") {
			hasBypass = true
		}
	}
	if !hasSpec {
		t.Error("expected API Specification Exposed finding")
	}
	if !hasBypass {
		t.Error("expected auth bypass finding for /admin/users")
	}
}

func TestScanAPISecurityNoSpecNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test"}
	findings := ScanAPISecurity(srv.Client(), cfg, core.CrawlResult{URL: srv.URL})
	if len(findings) != 0 {
		t.Fatalf("no spec on target, expected 0 findings, got %+v", findings)
	}
}

func TestParseAPISpecYAML(t *testing.T) {
	y := "openapi: 3.0.0\npaths:\n  /users:\n    get: {}\n  /posts/{id}:\n    get: {}\n"
	eps := parseAPISpec(y)
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints from YAML spec, got %v", eps)
	}
}

func TestParseAPISpecJSON(t *testing.T) {
	j := `{"swagger":"2.0","paths":{"/login":{"post":{}},"/logout":{"post":{}}}}`
	eps := parseAPISpec(j)
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints from JSON spec, got %v", eps)
	}
}
