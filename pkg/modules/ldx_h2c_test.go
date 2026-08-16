package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestScanLDAPXPathBoolean(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("filter")
		if strings.Contains(q, "uid=*") && !strings.Contains(q, "zzzz_nothing") {
			var rows strings.Builder
			rows.WriteString("<table>")
			for i := 0; i < 12; i++ {
				fmt.Fprintf(&rows, "<tr><td>user%d</td><td>cn=user%d,ou=people</td><td>mail:user%d@example.com</td></tr>", i, i, i)
			}
			rows.WriteString("</table>")
			fmt.Fprint(w, rows.String())
			return
		}
		fmt.Fprint(w, "<div>no results</div>")
	}))
	defer vuln.Close()

	cfg := &core.Config{}
	findings := ScanLDAPXPath(vuln.Client(), cfg, core.CrawlResult{URL: vuln.URL + "/search?filter=x"})
	if len(findings) == 0 {
		t.Fatal("expected LDAP boolean finding, got none")
	}
	if !strings.Contains(findings[0].Type, "LDAP") {
		t.Errorf("expected LDAP type, got %q", findings[0].Type)
	}
}

func TestScanLDAPXPathErrorLeak(t *testing.T) {
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("user")
		if strings.Contains(q, "*") || strings.Contains(q, ")") {
			fmt.Fprint(w, "Search failed: Invalid DN syntax (LDAP filter error)")
			return
		}
		fmt.Fprint(w, "login ok")
	}))
	defer leak.Close()

	cfg := &core.Config{}
	findings := ScanLDAPXPath(leak.Client(), cfg, core.CrawlResult{URL: leak.URL + "/login?user=x"})
	if len(findings) != 1 {
		t.Fatalf("expected error-leak finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Type, "error leak") {
		t.Errorf("expected error leak type, got %q", findings[0].Type)
	}
}

func TestScanLDAPXPathNoFPPageVocab(t *testing.T) {
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Search failed: Invalid DN syntax (LDAP filter error)")
	}))
	defer leak.Close()

	cfg := &core.Config{}
	findings := ScanLDAPXPath(leak.Client(), cfg, core.CrawlResult{URL: leak.URL + "/login?user=x"})
	for _, f := range findings {
		if strings.Contains(f.Type, "error leak") {
			t.Errorf("page that always shows LDAP error vocab must not be flagged, got %+v", findings)
		}
	}
}

func TestScanH2C(t *testing.T) {
	h2c := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}), &http2.Server{}))
	defer h2c.Close()

	cfg := &core.Config{}
	findings := ScanH2C(h2c.Client(), cfg, h2c.URL)
	if len(findings) != 1 {
		t.Fatalf("expected h2c finding on h2c-enabled server, got %d", len(findings))
	}

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer plain.Close()

	findings = ScanH2C(plain.Client(), cfg, plain.URL)
	if len(findings) != 0 {
		t.Errorf("plain HTTP/1.1 server must not produce h2c findings, got %v", findings)
	}
}
