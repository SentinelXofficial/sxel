package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestBroadDomainScopeParent(t *testing.T) {
	if !broadDomainScope("app.example.com", "example.com") {
		t.Fatal("expected broad scope when cookie Domain is a parent of page host")
	}
	if !broadDomainScope("app.example.com", ".example.com") {
		t.Fatal("expected broad scope with leading-dot Domain")
	}
}

func TestBroadDomainScopeExact(t *testing.T) {
	if broadDomainScope("app.example.com", "app.example.com") {
		t.Fatal("expected no broad scope when Domain equals page host")
	}
}

func TestBroadDomainScopeSibling(t *testing.T) {
	if broadDomainScope("app.example.com", "www.example.com") {
		t.Fatal("expected no broad scope for sibling subdomain")
	}
}

func TestBroadDomainScopeUnrelated(t *testing.T) {
	if broadDomainScope("127.0.0.1", "example.com") {
		t.Fatal("expected no broad scope for unrelated domain")
	}
}

func TestAuditCookiesBroadDomainFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc; Path=/; Domain=example.com")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	cfg := &core.Config{Verbose: false}
	results := AuditCookies(srv.Client(), cfg, srv.URL)
	for _, r := range results {
		if strings.Contains(r.Type, "Broad Domain Scope") {
			t.Fatalf("unexpected Broad Domain finding for unrelated domain")
		}
	}
}
