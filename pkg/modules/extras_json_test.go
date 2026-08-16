package modules

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func vulnJSONHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "GET" {
		w.Write([]byte(`{"search":"uncategorized","lang":"en"}`))
		return
	}
	raw, _ := io.ReadAll(r.Body)
	body := string(raw)
	if strings.Contains(body, "'") {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"SQLSTATE[42000]: syntax error at or near \"syntax error\""}`))
		return
	}
	w.Write([]byte(`{"status":"ok","q":"` + body + `"}`))
}

func TestScanJSONInjectionAPIBody(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(vulnJSONHandler))
	defer api.Close()

	cfg := &core.Config{}
	findings := ScanJSONInjection(api.Client(), cfg, core.CrawlResult{URL: api.URL + "/api/search"})
	if len(findings) == 0 {
		t.Fatal("expected SQLi finding on JSON API endpoint, got none")
	}
	ok := false
	for _, f := range findings {
		if strings.Contains(f.Type, "JSON API") && f.Parameter == "search" {
			ok = true
		}
	}
	if !ok {
		t.Errorf("expected JSON-API finding on parameter search, got %+v", findings)
	}
}

func TestScanJSONInjectionFormBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>page with a JSON form</html>"))
	})
	mux.HandleFunc("/search", vulnJSONHandler)
	endpoint := httptest.NewServer(mux)
	defer endpoint.Close()

	form := core.Form{
		Action: endpoint.URL + "/search",
		Method: "POST",
		Inputs: []core.Input{{Name: "q", Type: "text"}},
	}
	cfg := &core.Config{}
	findings := ScanJSONInjection(endpoint.Client(), cfg, core.CrawlResult{URL: endpoint.URL + "/page", Forms: []core.Form{form}})
	if len(findings) == 0 {
		t.Fatal("expected SQLi finding via JSON form body, got none")
	}
	for _, f := range findings {
		if f.URL != endpoint.URL+"/search" {
			t.Errorf("form finding should target the form action, got %s", f.URL)
		}
	}
}
