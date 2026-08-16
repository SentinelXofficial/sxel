package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestMatchWebShell(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		detected bool
		signal   string
	}{
		{"c99 shell", `<?php /* c99shell */ echo "x";`, true, "c99shell"},
		{"b374k", `<?php define('b374k','1'); ?>`, true, "b374k"},
		{"wso obfuscated", `<?php $a="wso4"; ?>`, true, "wso4"},
		{"eval POST shell", `<?php @eval($_POST['x']); ?>`, true, "eval($_post"},
		{"base64 eval", `<?php eval(base64_decode($_POST['q'])); ?>`, true, "base64_decode($_post"},
		{"obfuscated gzip", `<?php eval(gzinflate(base64_decode('....'))); ?>`, true, "eval(gzinflate"},
		{"generic markers x3", `<?php echo base64_decode(gzinflate(str_rot13('a'))); ?>`, true, ""},
		{"normal php page", `<?php echo "hello"; ?><html><body>home</body></html>`, false, ""},
		{"normal html", `<html><body><h1>Welcome</h1><p>about us</p></body></html>`, false, ""},
		{"empty", ``, false, ""},
		{"json api", `{"status":"ok","data":[]}`, false, ""},
	}
	for _, tc := range cases {
		got, sig := matchWebShell(tc.body)
		if got != tc.detected {
			t.Errorf("%s: match = %v, want %v", tc.name, got, tc.detected)
			continue
		}
		if !tc.detected {
			continue
		}
		if tc.signal != "" && sig != tc.signal {
			t.Errorf("%s: signal = %q, want %q", tc.name, sig, tc.signal)
		}
		if tc.signal == "" && webShellStrongContains(sig) {
			t.Errorf("%s: generic detection returned strong signal %q", tc.name, sig)
		}
	}
}

func TestRandomHex(t *testing.T) {
	a := randomHex(6)
	b := randomHex(6)
	if len(a) != 6 || len(b) != 6 {
		t.Fatalf("randomHex length: %q %q", a, b)
	}
	if a == b {
		t.Fatal("randomHex returned the same value twice")
	}
	for _, c := range a {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex char in %q", a)
		}
	}
}

func TestScanWebShellConfirmedExec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/uploads/shell.php":
			cmd := r.URL.Query().Get("cmd")
			if cmd == "" {
				r.ParseForm()
				cmd = r.Form.Get("cmd")
			}
			fmt.Fprintf(w, "<pre>output of: %s</pre>", cmd)
		case "/c99.php":
			fmt.Fprint(w, `<?php /* c99shell */ if(isset($_POST['cmd'])){echo "blocked";} ?><html>Mini Shell</html>`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer srv.Close()

	cfg := &core.Config{Timeout: 10, UserAgent: "test"}
	client := core.NewHTTPClient(cfg)
	results := ScanWebShell(client, cfg, core.CrawlResult{URL: srv.URL + "/"})

	var confirmed, passive bool
	for _, r := range results {
		if r.Type == "WebShell Confirmed (Remote Code Execution)" {
			confirmed = true
			if r.Severity != "CRITICAL" {
				t.Errorf("confirmed RCE severity = %s, want CRITICAL", r.Severity)
			}
			if !strings.Contains(r.Payload, "echo") {
				t.Errorf("confirmed RCE payload = %q, want echo probe", r.Payload)
			}
		}
		if r.Type == "WebShell Detected" && strings.Contains(r.URL, "c99.php") {
			passive = true
		}
	}
	if !confirmed {
		t.Error("expected a confirmed RCE finding for the live shell")
	}
	if !passive {
		t.Error("expected a passive detection for the c99.php fingerprint")
	}
}

func TestScanWebShellCleanTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/shell") || strings.Contains(r.URL.Path, ".php") {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "<html><body><h1>Clean site</h1></body></html>")
	}))
	defer srv.Close()

	cfg := &core.Config{Timeout: 10, UserAgent: "test"}
	client := core.NewHTTPClient(cfg)
	results := ScanWebShell(client, cfg, core.CrawlResult{URL: srv.URL + "/"})
	if len(results) != 0 {
		t.Errorf("clean target produced %d findings, want 0", len(results))
	}
}
