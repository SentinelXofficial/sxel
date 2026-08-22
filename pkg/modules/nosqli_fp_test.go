package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

// A WAF-style 403 on the operator payload must not be reported as a
// boolean-based NoSQLi finding.
func TestNoSQLiStatusDriftNoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		for k := range q {
			if len(k) > 4 && (k[len(k)-4:] == "[$ne]" || k[len(k)-4:] == "[$eq]") {
				w.WriteHeader(403)
				fmt.Fprint(w, "blocked")
				return
			}
			if k == "id" {
				fmt.Fprint(w, "normal page for id")
				return
			}
		}
		fmt.Fprint(w, strings.Repeat("A", 500))
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test"}
	client := srv.Client()
	res := ScanNoSQLi(client, cfg, core.CrawlResult{URL: srv.URL + "/?id=1"})
	for _, r := range res {
		if r.Type == "NoSQL Injection (Boolean-Based)" {
			t.Fatalf("status-drift 403 misreported as boolean NoSQLi: %+v", r)
		}
	}
}

func TestNoSQLiBooleanStillDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		for k, vs := range q {
			v := ""
			if len(vs) > 0 {
				v = vs[0]
			}
			if len(k) > 4 && (k[len(k)-4:] == "[$ne]" || k[len(k)-5:] == "[$gt]") &&
				(v == "xyz_nonexistent_0123456789" || v == "") {
				fmt.Fprint(w, strings.Repeat("TRUE", 300))
				return
			}
		}
		fmt.Fprint(w, "baseline-ish body content")
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test"}
	client := srv.Client()
	res := ScanNoSQLi(client, cfg, core.CrawlResult{URL: srv.URL + "/?id=1"})
	found := false
	for _, r := range res {
		if r.Type == "NoSQL Injection (Boolean-Based)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("genuine boolean NoSQLi not detected, got: %+v", res)
	}
}
