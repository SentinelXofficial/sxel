package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestAnalyzeXSSContext(t *testing.T) {
	inert := []struct{ body, pld string }{
		{"<title>a<script>alert(1)</script></title>", "<script>alert(1)</script>"},
		{"<!-- <script>alert(1)</script> -->", "<script>alert(1)</script>"},
		{"<textarea><script>alert(1)</script></textarea>", "<script>alert(1)</script>"},
		{"<input value=\"<script>alert(1)</script>\">", "<script>alert(1)</script>"},
		{"<pre>you searched for: &lt;script&gt;</pre>", "<script>"},
		{"<script>var x=1;<img src=x onerror=alert(1)></script>", "<img src=x onerror=alert(1)>"},
		{"<input value=\"javascript:alert(1)\">", "javascript:alert(1)"},
	}
	for _, c := range inert {
		ctx, exec := analyzeXSSContext(c.body, c.pld)
		if exec {
			t.Errorf("expected inert context for %q (pld %q), got exec=%v ctx=%q", c.body, c.pld, exec, ctx)
		}
	}
	exec := []struct{ body, pld string }{
		{"<p>hi <script>alert(1)</script></p>", "<script>alert(1)</script>"},
		{"<SCRIPT>var x=1;<script>alert(1)</script></SCRIPT>", "<script>alert(1)</script>"},
		{"<input value=\"x\">\"><svg onload=alert(1)></svg>", "\"><svg onload=alert(1)></svg>"},
		{"<a href=\"x\">hi\"><script>alert(1)</script></a>", "\"><script>alert(1)</script>"},
		{"<img onerror=\"<script>alert(1)</script>\">", "<script>alert(1)</script>"},
		{"<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>", "<script>alert(1)</script>"},
		{"<input value=\"x\" onerror=alert(1)>", "\" onerror=alert(1)"},
		{"<a href=\"javascript:alert(1)\" >x</a>", "\"javascript:alert(1)"},
		{"<script>var t = `${alert(1)}`; var x = 1</script>", "${alert(1)}"},
		{"<p>İstanbul da <script>alert(1)</script></p>", "<script>alert(1)</script>"},
	}
	for _, c := range exec {
		ctx, ok := analyzeXSSContext(c.body, c.pld)
		if !ok {
			t.Errorf("expected executable context for %q (pld %q), got ctx=%q", c.body, c.pld, ctx)
		}
	}
}

func TestAnalyzeXSSContextEntityBreakout(t *testing.T) {
	body := "<input value=\"x&quot;&gt;&lt;svg onload=alert(1)&gt;&lt;/svg&gt;\">"
	pld := "\"><svg onload=alert(1)></svg>"
	ctx, exec := analyzeXSSContext(body, pld)
	if !exec || ctx != "html attribute (entity breakout)" {
		t.Errorf("encoded payload inside quoted attribute must be executable breakout, got exec=%v ctx=%q", exec, ctx)
	}
}

func TestAnalyzeXSSContextWorstOccurrence(t *testing.T) {
	body := "<title>safe <script>alert(1)</script></title><p>evil <script>alert(1)</script></p>"
	pld := "<script>alert(1)</script>"
	ctx, exec := analyzeXSSContext(body, pld)
	if !exec || ctx != "text node" {
		t.Errorf("second occurrence in text node must win over inert first, got exec=%v ctx=%q", exec, ctx)
	}
}

func TestXSSInertThenBreakoutPayoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "<svg") {
			w.Write([]byte("<html><p>you searched: " + q + "</p></html>"))
		} else {
			w.Write([]byte("<html><title>you searched: " + q + "</title></html>"))
		}
	}))
	defer srv.Close()

	cfg := &core.Config{}
	findings := ScanXSS(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/?q=x"})
	hasXSS := false
	hasRefl := false
	for _, f := range findings {
		if strings.Contains(f.Type, "XSS (Reflected)") {
			hasXSS = true
		}
		if strings.Contains(f.Type, "Reflected input") {
			hasRefl = true
		}
	}
	if !hasXSS {
		t.Errorf("breakout payload must be tried even after inert match, findings=%+v", findings)
	}
	if hasRefl && hasXSS {
		t.Errorf("inert finding must not be reported when breakout payload proved XSS")
	}
}

func TestXSSEncodedReflection(t *testing.T) {
	repl := strings.NewReplacer("<", "&lt;", ">", "&gt;", "\"", "&quot;")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		q = strings.ToUpper(q)
		if r.URL.Query().Get("ctx") == "attr" {
			w.Write([]byte("<html><input value=\"x" + repl.Replace(q) + "\"></html>"))
			return
		}
		w.Write([]byte("<html><p>echo: " + repl.Replace(q) + "</p></html>"))
	}))
	defer srv.Close()

	cfg := &core.Config{}

	textFindings := ScanXSS(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/?q=x&ctx=text"})
	for _, f := range textFindings {
		if strings.Contains(f.Type, "XSS") || strings.Contains(f.Type, "Reflected input") {
			t.Errorf("entity-encoded reflection in text node is inert and must not be reported, got %+v", f)
		}
	}

	attrFindings := ScanXSS(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/?q=x&ctx=attr"})
	hasXSS := false
	for _, f := range attrFindings {
		if strings.Contains(f.Type, "XSS (Reflected)") {
			hasXSS = true
		}
	}
	if !hasXSS {
		t.Errorf("entity-encoded breakout inside quoted attribute must be XSS, got %+v", attrFindings)
	}
}

func TestScanXSSContextualSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>search: " + q + "</title></html>"))
	}))
	defer srv.Close()

	cfg := &core.Config{}
	findings := ScanXSS(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/?q=x"})
	hasBreakout := false
	for _, f := range findings {
		if strings.Contains(f.Type, "XSS (Reflected)") {
			hasBreakout = true
		}
	}
	if !hasBreakout {
		t.Errorf("title breakout (</title><script>) must be reported as XSS, got %+v", findings)
	}
}

func TestScanXSSInertTitleTextLow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>search: " + strings.ReplaceAll(strings.ReplaceAll(q, "<", "&lt;"), ">", "&gt;") + "</title></html>"))
	}))
	defer srv.Close()

	cfg := &core.Config{}
	findings := ScanXSS(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/?q=x"})
	for _, f := range findings {
		if strings.Contains(f.Type, "XSS") {
			t.Errorf("escaped title reflection must not be XSS, got %+v", f)
		}
		if strings.Contains(f.Type, "Reflected input") && f.Severity != "LOW" {
			t.Errorf("inert reflection must be LOW, got %s", f.Severity)
		}
	}
}

func TestScanXSSExecutableContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><p>you searched: " + q + "</p></html>"))
	}))
	defer srv.Close()

	cfg := &core.Config{}
	findings := ScanXSS(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/?q=x"})
	hasXSS := false
	for _, f := range findings {
		if strings.Contains(f.Type, "XSS (Reflected)") && f.Severity == "MEDIUM" {
			hasXSS = true
		}
	}
	if !hasXSS {
		t.Errorf("text-node reflection must be reported as XSS, got %+v", findings)
	}
}
