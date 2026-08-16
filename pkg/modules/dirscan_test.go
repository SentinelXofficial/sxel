package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func testCfg() *core.Config {
	return &core.Config{
		Threads:   5,
		Timeout:   5,
		UserAgent: "sxel-test",
	}
}

func collectTypes(results []core.ScanResult) map[string]bool {
	out := map[string]bool{}
	for _, r := range results {
		out[r.URL] = true
	}
	return out
}

func TestScanDirsRatioFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			fmt.Fprintf(w, "%s", strings.Repeat("real page with distinct content length here ", 12))
		case "/soft404":
			fmt.Fprintf(w, "<html>not found</html>")
		default:
			fmt.Fprintf(w, "<html>not found</html>")
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	results := ScanDirsV2(client, testCfg(), srv.URL, DirScanOpts{})
	urls := collectTypes(results)
	if !urls[srv.URL+"/admin"] {
		t.Errorf("expected /admin hit, got %v", urls)
	}
	if urls[srv.URL+"/soft404"] {
		t.Error("soft-404 should be filtered by baseline ratio")
	}
}

func TestScanDirsExtensionStacking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/config":
			fmt.Fprintf(w, "<html>not found</html>")
		case "/config.bak":
			fmt.Fprintf(w, "%s", strings.Repeat("backup config contents with real data ", 10))
		default:
			fmt.Fprintf(w, "<html>not found</html>")
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	results := ScanDirsV2(client, testCfg(), srv.URL, DirScanOpts{Exts: []string{".bak"}})
	urls := collectTypes(results)
	if !urls[srv.URL+"/config.bak"] {
		t.Errorf("extension stacking should find /config.bak, got %v", urls)
	}
	if urls[srv.URL+"/config"] {
		t.Error("plain /config should stay a soft-404 miss")
	}
}

func TestScanDirsRecursive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.Header().Set("Location", "/admin/")
			w.WriteHeader(302)
		case "/admin/":
			fmt.Fprintf(w, "admin index")
		case "/admin/panel":
			fmt.Fprintf(w, "%s", strings.Repeat("panel contents with unique body ", 8))
		default:
			fmt.Fprintf(w, "<html>not found</html>")
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	results := ScanDirsV2(client, testCfg(), srv.URL, DirScanOpts{Depth: 1})
	urls := collectTypes(results)
	if !urls[srv.URL+"/admin"] {
		t.Errorf("expected /admin hit, got %v", urls)
	}
	if !urls[srv.URL+"/admin/panel"] {
		t.Errorf("recursive depth 1 should find /admin/panel, got %v", urls)
	}
}

func TestScanDirsContentCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			fmt.Fprintf(w, "DB_HOST=db.internal\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\npassword=\"hunter2secret\"\n%s", strings.Repeat("EXTRA=padding-for-length\n", 10))
			return
		}
		fmt.Fprintf(w, "<html>not found</html>")
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	results := ScanDirsV2(client, testCfg(), srv.URL, DirScanOpts{ContentCheck: true})
	var secretFindings []string
	for _, r := range results {
		if r.Type == "Secret in Exposed File" {
			secretFindings = append(secretFindings, r.URL+"|"+r.Payload)
		}
	}
	joined := strings.Join(secretFindings, ";")
	if !strings.Contains(joined, srv.URL+"/.env|AWS access key") {
		t.Errorf("expected AWS access key finding, got %v", secretFindings)
	}
	if !strings.Contains(joined, "Password assignment") {
		t.Errorf("expected password assignment finding, got %v", secretFindings)
	}
}

func TestSensitiveFile(t *testing.T) {
	cases := map[string]bool{
		".env":            true,
		"backup.zip":      true,
		"config.php":      true,
		"dump.sql":        true,
		"index.html":      false,
		"images/logo.png": false,
		".git/HEAD":       true,
		"web.config":      true,
	}
	for path, want := range cases {
		if got := sensitiveFile(path); got != want {
			t.Errorf("sensitiveFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestContentCheckRegexes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ghp_%s secret", strings.Repeat("A", 36))
	}))
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	results := contentCheck(client, testCfg(), srv.URL)
	if len(results) == 0 {
		t.Fatal("expected GitHub token finding")
	}
	if results[0].Severity != "HIGH" {
		t.Errorf("severity = %s, want HIGH", results[0].Severity)
	}
}

func TestScanDirsFallbackOnWordlistError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	defer srv.Close()
	cfg := testCfg()
	cfg.Wordlist = "/nonexistent/wordlist.txt"
	client := &http.Client{Timeout: 5 * time.Second}
	results := ScanDirsV2(client, cfg, srv.URL, DirScanOpts{})
	_ = results
}
