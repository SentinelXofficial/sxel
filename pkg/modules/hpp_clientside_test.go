package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestScanHPP(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals, ok := r.URL.Query()["q"]
		if !ok {
			fmt.Fprintf(w, "q=missing")
			return
		}
		fmt.Fprintf(w, "search: %s", strings.Join(vals, "+"))
	}))
	defer vuln.Close()

	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "search: %s", r.URL.Query().Get("q"))
	}))
	defer safe.Close()

	cfg := &core.Config{}
	findings := ScanHPP(vuln.Client(), cfg, core.CrawlResult{URL: vuln.URL + "/list?q=apple"})
	if len(findings) == 0 {
		t.Fatal("expected HPP finding on concatenating server, got none")
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("concatenation should be HIGH, got %s", findings[0].Severity)
	}

	findings = ScanHPP(safe.Client(), cfg, core.CrawlResult{URL: safe.URL + "/list?q=apple"})
	if len(findings) != 0 {
		t.Errorf("first-value-wins server must not flag HPP, got %v", findings)
	}
}

func TestScanHPPPostForm(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		vals := r.PostForm["q"]
		if len(vals) > 1 && strings.Contains(vals[1], "hppx") {
			fmt.Fprintf(w, "both: %s+%s", vals[0], vals[1])
			return
		}
		fmt.Fprintf(w, "single: %s", strings.Join(vals, "+"))
	}))
	defer endpoint.Close()

	form := core.Form{
		Action: endpoint.URL + "/go",
		Method: "POST",
		Inputs: []core.Input{{Name: "q", Type: "text"}},
	}
	cfg := &core.Config{}
	findings := ScanHPP(endpoint.Client(), cfg, core.CrawlResult{URL: endpoint.URL + "/page", Forms: []core.Form{form}})
	if len(findings) != 1 || findings[0].Method != "POST" {
		t.Errorf("expected 1 POST HPP finding, got %+v", findings)
	}
}

func TestScanDOMAudit(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Write([]byte(`document.getElementById("x").innerHTML = location.hash.slice(1);`))
			return
		}
		fmt.Fprintf(w, `<html><body><script>
var m = location.hash;
document.body.insertAdjacentHTML("beforeend", m);
window.addEventListener("message", function(e) { document.write(e.data); });
</script><script src="%s/app.js"></script></body></html>`, r.Host)
	}))
	defer page.Close()

	cfg := &core.Config{}
	findings := ScanDOMAudit(page.Client(), cfg, page.URL+"/index.html")
	types := map[string]bool{}
	for _, f := range findings {
		types[f.Type] = true
	}
	if !types["DOM XSS candidate (static)"] {
		t.Errorf("expected DOM XSS candidate finding, got %v", types)
	}
	if !types["postMessage listener without origin check"] {
		t.Errorf("expected postMessage finding, got %v", types)
	}
}
