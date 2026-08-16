package modules

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestFingerprintDBMS(t *testing.T) {
	cases := map[string]string{
		"you have an error in your sql syntax near '1'' at line 1":                "mysql",
		"Warning: pg_query(): Query failed: ERROR: syntax error at or near \"'\"": "postgresql",
		"Unclosed quotation mark after the character string 'sxel2nd1'.":          "mssql",
		"ORA-01756: quoted string not properly terminated":                        "oracle",
		"SQLite3::execute(): near \"'\": syntax error":                            "sqlite",
		"java.sql.SQLException: ORA-00933: SQL command not properly ended":        "oracle",
		"nothing suspicious here":                                                 "",
	}
	for body, want := range cases {
		if got := fingerprintDBMS(body); got != want {
			t.Fatalf("fingerprintDBMS(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestUnionOracleFromDual(t *testing.T) {
	probe, control, mp, mc := unionPair(unionVariants()[6], 2, 1)
	if !strings.Contains(probe, "FROM dual") || !strings.Contains(control, "FROM dual") {
		t.Fatalf("oracle variant missing FROM dual: %q | %q", probe, control)
	}
	if mp == mc {
		t.Fatal("markers must differ")
	}
}

func TestUnionOracleVariantDetects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		switch {
		case strings.Contains(q, "UNION SELECT 1,2 FROM dual"):
			io.WriteString(w, "value=2")
		case strings.Contains(q, "UNION SELECT 1,3 FROM dual"):
			io.WriteString(w, "value=3")
		default:
			io.WriteString(w, "value=1")
		}
	}))
	defer srv.Close()
	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	target := core.CrawlResult{URL: srv.URL + "/p?id=1"}
	res := scanUnionURL(client, cfg, target.URL, "id")
	if len(res) == 0 {
		t.Fatal("oracle union variant should detect union injection")
	}
}

func TestSecondOrderSQLiDetects(t *testing.T) {
	stored := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == "POST" {
			stored = r.FormValue("name")
			io.WriteString(w, "saved")
			return
		}
		if strings.Contains(stored, "sxel2nd") && !strings.Contains(stored, "--") {
			io.WriteString(w, "error: you have an error in your sql syntax near stored name")
			return
		}
		io.WriteString(w, "profile: "+stored)
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	form := core.Form{
		Method: "POST", Action: srv.URL + "/save",
		Inputs: []core.Input{{Name: "name"}},
	}
	target := core.CrawlResult{URL: srv.URL + "/profile", Forms: []core.Form{form}}
	res := ScanSecondOrderSQLi(client, cfg, target)
	if len(res) == 0 {
		t.Fatal("second-order sqli not detected")
	}
	if !strings.Contains(res[0].Type, "mysql") {
		t.Fatalf("dbms fingerprint missing in type: %q", res[0].Type)
	}
	if res[0].Method != "POST" || res[0].Parameter != "name" {
		t.Fatalf("finding metadata wrong: %+v", res[0])
	}
}

func TestSecondOrderNoFPOnSafeStore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == "POST" {
			io.WriteString(w, "saved ok")
			return
		}
		io.WriteString(w, "profile page clean")
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test", Scope: []string{srv.URL}}
	client := core.NewHTTPClient(cfg)
	form := core.Form{
		Method: "POST", Action: srv.URL + "/save",
		Inputs: []core.Input{{Name: "name"}},
	}
	target := core.CrawlResult{URL: srv.URL + "/profile", Forms: []core.Form{form}}
	if res := ScanSecondOrderSQLi(client, cfg, target); len(res) != 0 {
		t.Fatalf("false positive: %+v", res)
	}
}
