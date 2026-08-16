package modules

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/miekg/dns"
)

func mustParseRRs(lines []string) []dns.RR {
	var rrs []dns.RR
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			panic(err)
		}
		rrs = append(rrs, rr)
	}
	return rrs
}

func newTestDNSServer(handler dns.HandlerFunc) *dns.Server {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	srv := &dns.Server{Addr: ln.Addr().String(), Listener: ln, Handler: handler}
	go srv.ActivateAndServe()
	return srv
}

func massAssignHandler(assign func(w http.ResponseWriter, r *http.Request, body map[string]any)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"id":1,"name":"demo"}`))
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"bad json"}`))
			return
		}
		assign(w, r, body)
	}
}

func TestScanMassAssignmentVulnerable(t *testing.T) {
	srv := httptest.NewServer(massAssignHandler(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		if v, ok := body["is_admin"].(bool); ok && v {
			w.Write([]byte(`{"id":1,"name":"demo","is_admin":true,"role":"granted"}`))
			return
		}
		w.Write([]byte(`{"id":1,"name":"demo"}`))
	}))
	defer srv.Close()

	cfg := &core.Config{}
	findings := ScanMassAssignment(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/api/users"})
	found := false
	for _, f := range findings {
		if strings.Contains(f.Type, "Mass assignment") && f.Parameter == "is_admin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected mass assignment finding, got %+v", findings)
	}
}

func TestScanMassAssignmentSafe(t *testing.T) {
	srv := httptest.NewServer(massAssignHandler(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		w.Write([]byte(`{"id":1,"name":"demo"}`))
	}))
	defer srv.Close()

	cfg := &core.Config{}
	findings := ScanMassAssignment(srv.Client(), cfg, core.CrawlResult{URL: srv.URL + "/api/users"})
	if len(findings) != 0 {
		t.Fatalf("expected no findings for whitelisted server, got %+v", findings)
	}
}

func TestScanAXFROpen(t *testing.T) {
	records := []string{
		"example.test.\t3600\tIN\tSOA\tns1.example.test. admin.example.test. 1 7200 900 1209600 86400",
		"example.test.\t3600\tIN\tNS\tns1.example.test.",
		"www.example.test.\t3600\tIN\tA\t192.0.2.10",
		"mail.example.test.\t3600\tIN\tA\t192.0.2.11",
	}
	srv := newTestDNSServer(func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeAXFR {
			rr := mustParseRRs(records)
			m1 := new(dns.Msg)
			m1.SetReply(r)
			m1.Authoritative = true
			m1.Answer = rr
			w.WriteMsg(m1)
			m2 := new(dns.Msg)
			m2.SetReply(r)
			m2.Authoritative = true
			m2.Answer = rr[:1]
			w.WriteMsg(m2)
			return
		}
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
	})
	defer srv.Shutdown()

	cfg := &core.Config{}
	findings := ScanAXFR(&http.Client{}, cfg, "http://www.example.test/", srv.Addr)
	if len(findings) != 1 {
		t.Fatalf("expected 1 AXFR finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Evidence, "192.0.2.10") {
		t.Errorf("evidence should contain transferred record, got %q", findings[0].Evidence)
	}
}

func TestScanAXFRClosed(t *testing.T) {
	srv := newTestDNSServer(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
	})
	defer srv.Shutdown()

	cfg := &core.Config{}
	findings := ScanAXFR(&http.Client{}, cfg, "http://www.example.test/", srv.Addr)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for closed zone, got %+v", findings)
	}
}
