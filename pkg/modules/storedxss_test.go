package modules

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestStoredXSSDetects(t *testing.T) {
	stored := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == "POST" {
			stored = r.FormValue("name")
			io.WriteString(w, "saved")
			return
		}
		io.WriteString(w, "<html><body>profile: "+stored+"</body></html>")
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	form := core.Form{
		Method: "POST", Action: srv.URL + "/save",
		Inputs: []core.Input{{Name: "name"}},
	}
	target := core.CrawlResult{URL: srv.URL + "/profile", Forms: []core.Form{form}}
	res := ScanStoredXSS(client, cfg, target)
	if len(res) == 0 {
		t.Fatal("stored xss not detected")
	}
	if res[0].Type != "Stored XSS via Form" || res[0].Parameter != "name" {
		t.Fatalf("finding metadata wrong: %+v", res[0])
	}
}

func TestStoredXSSNoFPWhenEscaped(t *testing.T) {
	stored := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == "POST" {
			stored = r.FormValue("name")
			io.WriteString(w, "saved")
			return
		}
		io.WriteString(w, "profile: "+escapeHTMLText(stored))
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	form := core.Form{
		Method: "POST", Action: srv.URL + "/save",
		Inputs: []core.Input{{Name: "name"}},
	}
	target := core.CrawlResult{URL: srv.URL + "/profile", Forms: []core.Form{form}}
	if res := ScanStoredXSS(client, cfg, target); len(res) != 0 {
		t.Fatalf("escaped payload must not be reported: %+v", res)
	}
}

func TestStoredXSSNoFPWithoutDisplay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == "POST" {
			io.WriteString(w, "saved")
			return
		}
		io.WriteString(w, "no user content here")
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	form := core.Form{
		Method: "POST", Action: srv.URL + "/save",
		Inputs: []core.Input{{Name: "name"}},
	}
	target := core.CrawlResult{URL: srv.URL + "/profile", Forms: []core.Form{form}}
	if res := ScanStoredXSS(client, cfg, target); len(res) != 0 {
		t.Fatalf("no display page should not trigger: %+v", res)
	}
}

func escapeHTMLText(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&#34;",
		"'", "&#39;",
	)
	return r.Replace(s)
}
