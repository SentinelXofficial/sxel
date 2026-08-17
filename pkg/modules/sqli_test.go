package modules

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/engine"
)

func TestUnionPairSameLength(t *testing.T) {
	for _, v := range unionVariants() {
		for n := 1; n <= unionMaxCols; n++ {
			probe, control, _, _ := unionPair(v, n, 1)
			if probe == control {
				t.Errorf("probe must differ from control (variant %q, cols %d)", v.quote+v.comment, n)
			}
			if len(probe) != len(control) {
				t.Errorf("probe/control must be same length for reflection safety: %q (%d) vs %q (%d)", probe, len(probe), control, len(control))
			}
		}
	}
}

func TestConsistentClassSplit(t *testing.T) {
	cases := []struct {
		name   string
		splits []boolSplit
		want   bool
	}{
		{"two same-direction significant", []boolSplit{{diff: 300, significant: true}, {diff: 250, significant: true}}, true},
		{"three incl one small", []boolSplit{{diff: 300, significant: true}, {diff: 250, significant: true}, {diff: 10, significant: false}}, true},
		{"opposite directions", []boolSplit{{diff: 300, significant: true}, {diff: -250, significant: true}}, false},
		{"only one significant", []boolSplit{{diff: 300, significant: true}, {diff: 10, significant: false}}, false},
		{"none significant", []boolSplit{{diff: 10, significant: false}, {diff: -10, significant: false}}, false},
	}
	for _, c := range cases {
		if got := consistentClassSplit(c.splits); got != c.want {
			t.Errorf("%s: consistentClassSplit = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestConfirmedTiming(t *testing.T) {
	if !confirmed(&core.Config{}, 2*time.Second, 3*time.Second, 8) {
		t.Error("1.5x scaled confirm should pass")
	}
	if !confirmed(&core.Config{}, 3*time.Second, 5*time.Second, 8) {
		t.Error("confirm near full sleep should pass")
	}
	if confirmed(&core.Config{}, 3*time.Second, 300*time.Millisecond, 8) {
		t.Error("noise-level confirm must fail")
	}
	if confirmed(&core.Config{}, 0, 5*time.Second, 8) {
		t.Error("zero first delta must fail")
	}
}

func TestScanUnionSQLi(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if idx := strings.Index(q, "UNION SELECT "); idx >= 0 {
			cols := strings.Split(strings.Split(q[idx+len("UNION SELECT "):], "--")[0], ",")
			if len(cols) == 2 {
				fmt.Fprintf(w, `<html><table><tr><td>1</td><td>2</td></tr><tr><td>%s</td><td>%s</td></tr></table></html>`, cols[0], cols[1])
				return
			}
		}
		fmt.Fprintf(w, `<html>no results for %s</html>`, q)
	}))
	defer vuln.Close()

	reflect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html>you searched for: %s</html>`, r.URL.Query().Get("q"))
	}))
	defer reflect.Close()

	cfg := &core.Config{}
	cfg.Threads = 4

	findings := ScanUnionSQLi(vuln.Client(), cfg, core.CrawlResult{URL: vuln.URL + "/list?q=x"})
	if len(findings) != 1 {
		t.Fatalf("vulnerable endpoint: expected 1 union finding, got %d (%v)", len(findings), findings)
	}
	if !strings.Contains(findings[0].Type, "Union-Based") || !strings.Contains(findings[0].Type, "2 columns") {
		t.Errorf("expected 2-column union finding, got %q", findings[0].Type)
	}

	findings = ScanUnionSQLi(reflect.Client(), cfg, core.CrawlResult{URL: reflect.URL + "/r?q=x"})
	if len(findings) != 0 {
		t.Errorf("pure reflection must not produce union findings, got %v", findings)
	}
}

func TestScanBooleanBlindSQLi(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		rows := 1
		switch {
		case strings.Contains(q, "1=2"), strings.Contains(q, "'b"):
			rows = 0
		case strings.Contains(q, "1=1"), strings.Contains(q, "'a"):
			rows = 10
		}
		var sb strings.Builder
		sb.WriteString("<html>")
		for i := 0; i < rows; i++ {
			sb.WriteString("<div>item " + fmt.Sprint(i) + "</div>")
		}
		sb.WriteString("</html>")
		w.Write([]byte(sb.String()))
	}))
	defer vuln.Close()

	static := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>static page</html>"))
	}))
	defer static.Close()

	cfg := &core.Config{}
	cfg.Threads = 4

	findings := ScanBooleanBlindSQLi(vuln.Client(), cfg, core.CrawlResult{URL: vuln.URL + "/b?q=x"})
	if len(findings) != 1 {
		t.Fatalf("vulnerable endpoint: expected 1 boolean finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Type, "Boolean-Based") {
		t.Errorf("unexpected type %q", findings[0].Type)
	}

	findings = ScanBooleanBlindSQLi(static.Client(), cfg, core.CrawlResult{URL: static.URL + "/s?q=x"})
	if len(findings) != 0 {
		t.Errorf("static page must not produce boolean findings, got %v", findings)
	}
}

func laravelStyleFormServer(t *testing.T) *httptest.Server {
	var mu sync.Mutex
	cycle := 0
	msgs := []string{
		"These credentials do not match our records.",
		"The email field must be a valid email address.",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPost {
			cycle++
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		email := r.URL.Query().Get("old")
		w.Write([]byte(`<html><body><form method="POST" action="/login">` +
			`<input type="hidden" name="_token" value="tok1">` +
			`<input type="email" name="email" value="` + html.EscapeString(email) + `">` +
			`<input type="password" name="password">` +
			`<input type="checkbox" name="remember" value="1">` +
			`</form><div class="err" style="color:#ef4444">` + msgs[cycle%len(msgs)] + `</div></body></html>`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLaravelStyleFormNoSQLiFalsePositive(t *testing.T) {
	srv := laravelStyleFormServer(t)
	cfg := &core.Config{Threads: 2, UserAgent: "sxel-test"}
	client := core.NewHTTPClient(cfg)
	form := core.Form{
		Method: "POST", Action: srv.URL + "/login",
		TokenName: "_token", TokenValue: "tok1",
		Inputs: []core.Input{
			{Name: "email", Type: "email"},
			{Name: "password", Type: "password"},
			{Name: "remember", Type: "checkbox"},
		},
	}
	target := core.CrawlResult{URL: srv.URL + "/login", Forms: []core.Form{form}}

	if res := ScanUnionSQLi(client, cfg, target); len(res) != 0 {
		t.Fatalf("laravel-style form must not produce union findings, got %v", res)
	}
	if res := ScanBooleanBlindSQLi(client, cfg, target); len(res) != 0 {
		t.Fatalf("laravel-style form must not produce boolean findings, got %v", res)
	}
}

func TestEncodedReflectionNoUnionFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		enc := strings.ReplaceAll(html.EscapeString(q), " ", "&#32;")
		fmt.Fprintf(w, "<html>you searched for <b>%s</b></html>", enc)
	}))
	defer srv.Close()

	cfg := &core.Config{Threads: 2, UserAgent: "sxel-test"}
	client := core.NewHTTPClient(cfg)
	res := ScanUnionSQLi(client, cfg, core.CrawlResult{URL: srv.URL + "/r?q=x"})
	if len(res) != 0 {
		t.Fatalf("entity-encoded reflection must not produce union findings, got %v", res)
	}
}

func TestScanUnionSQLiFormVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			email := r.FormValue("email")
			if idx := strings.Index(email, "UNION SELECT "); idx >= 0 {
				cols := strings.Split(strings.Split(email[idx+len("UNION SELECT "):], "--")[0], ",")
				if len(cols) == 2 {
					fmt.Fprintf(w, "<html><table><tr><td>%s</td><td>%s</td></tr></table></html>", cols[0], cols[1])
					return
				}
			}
			fmt.Fprintf(w, "<html>no results for %s</html>", email)
			return
		}
		w.Write([]byte(`<html><form method="POST" action="/login"><input type="email" name="email"><input type="password" name="password"></form></html>`))
	}))
	defer srv.Close()

	cfg := &core.Config{Threads: 2, UserAgent: "sxel-test"}
	client := core.NewHTTPClient(cfg)
	fs, err := engine.FetchForms(client, cfg, srv.URL+"/login")
	if err != nil {
		t.Fatal(err)
	}
	res := ScanUnionSQLi(client, cfg, core.CrawlResult{URL: srv.URL + "/login", Forms: fs})
	if len(res) != 1 || !strings.Contains(res[0].Type, "2 columns") {
		t.Fatalf("expected 2-column union via form, got %v", res)
	}
}

func TestScanBlindSQLiTimeNegative(t *testing.T) {
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>ok</html>"))
	}))
	defer fast.Close()

	cfg := &core.Config{}
	findings := ScanBlindSQLiTime(fast.Client(), cfg, core.CrawlResult{URL: fast.URL + "/t?q=x"})
	if len(findings) != 0 {
		t.Errorf("fast static server must not produce time-based findings, got %v", findings)
	}
}

func TestScanBlindSQLiTimePositiveEarlyStop(t *testing.T) {
	var count int64
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		q := r.URL.Query().Get("q")
		switch {
		case strings.Contains(q, "SLEEP(5)"):
			time.Sleep(5 * time.Second)
		case strings.Contains(q, "SLEEP(3)"):
			time.Sleep(3 * time.Second)
		}
		w.Write([]byte("<html>ok</html>"))
	}))
	defer vuln.Close()

	cfg := &core.Config{}
	findings := ScanBlindSQLiTime(vuln.Client(), cfg, core.CrawlResult{URL: vuln.URL + "/t?q=x"})
	if len(findings) != 1 {
		t.Fatalf("sleeping endpoint: expected 1 time-based finding, got %d (%v)", len(findings), findings)
	}
	if !strings.Contains(findings[0].Type, "MySQL") {
		t.Errorf("expected MySQL finding, got %q", findings[0].Type)
	}
	if n := atomic.LoadInt64(&count); n > 8 {
		t.Errorf("expected early stop (~6 requests: 3 baseline + 1 quick + 2 verify), got %d", n)
	}
}
