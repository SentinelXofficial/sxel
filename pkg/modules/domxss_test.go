package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestScanDOMXSSScriptContext(t *testing.T) {
	if core.ChromePath() == "" {
		t.Skip("Chrome/Chromium not available — set SXEL_CHROME to enable")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><script>var search = %q;</script></html>", q)
	}))
	defer srv.Close()

	cfg := &core.Config{}
	findings := ScanDOMXSS(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/p?q=x"})
	found := false
	for _, f := range findings {
		if strings.Contains(f.Type, "DOM-verified XSS") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DOM-verified XSS finding, got %+v", findings)
	}
}

func TestScanDOMXSSInertReflection(t *testing.T) {
	if core.ChromePath() == "" {
		t.Skip("Chrome/Chromium not available — set SXEL_CHROME to enable")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><p>you searched: %s</p></html>", q)
	}))
	defer srv.Close()

	cfg := &core.Config{}
	findings := ScanDOMXSS(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/p?q=x"})
	for _, f := range findings {
		if strings.Contains(f.Type, "DOM-verified XSS") {
			t.Errorf("plain-text reflection must not be verified XSS, got %+v", f)
		}
	}
}
