package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func startTestProxy(t *testing.T, scope []string) (*MITM, string) {
	t.Helper()
	return startTestProxyAt(t, scope, filepath.Join(t.TempDir(), "ca"))
}

func startTestProxyAt(t *testing.T, scope []string, caDir string) (*MITM, string) {
	t.Helper()
	mitm, err := NewMITM(caDir, scope)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mitm}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return mitm, ln.Addr().String()
}

func TestProxyHTTPPassiveFindings(t *testing.T) {
	var target http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "TestApp")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
		io.WriteString(w, "<html><body>hello</body></html>")
	})
	targetSrv := httptest.NewServer(target)
	defer targetSrv.Close()

	mitm, proxyAddr := startTestProxy(t, nil)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, "http://"+proxyAddr))}}
	resp, err := client.Get(targetSrv.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	findings := mitm.Findings()
	if len(findings) == 0 {
		t.Fatal("no passive findings")
	}
	types := map[string]bool{}
	for _, f := range findings {
		types[f.Type] = true
	}
	for _, want := range []string{"Missing Security Header", "Cookie Missing HttpOnly", "Cookie Missing Secure"} {
		if !types[want] {
			t.Fatalf("expected finding %q, got %v", want, types)
		}
	}
}

func TestProxyHTTPSMITM(t *testing.T) {
	targetSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		io.WriteString(w, "secure page")
	}))
	defer targetSrv.Close()

	caDir := filepath.Join(t.TempDir(), "ca")
	mitm, proxyAddr := startTestProxyAt(t, nil, caDir)

	transport := &http.Transport{
		Proxy: http.ProxyURL(mustURL(t, "http://"+proxyAddr)),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(targetSrv.URL + "/secure")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "secure page") {
		t.Fatalf("MITM tunnel broken: %q", body)
	}
	found := false
	for _, f := range mitm.Findings() {
		if f.Type == "Missing Security Header" && f.Parameter == "strict-transport-security" {
			found = true
		}
	}
	if !found {
		t.Fatalf("HSTS missing not reported: %+v", mitm.Findings())
	}
}

func TestProxyScopeFilter(t *testing.T) {
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer targetSrv.Close()

	mitm, proxyAddr := startTestProxy(t, []string{"unrelated.example"})
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, "http://"+proxyAddr))}}
	resp, err := client.Get(targetSrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if len(mitm.Findings()) != 0 {
		t.Fatalf("out-of-scope host analyzed: %+v", mitm.Findings())
	}
}

func TestProxySensitiveDetection(t *testing.T) {
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "AKIAIOSFODNN7EXAMPLE not secret but pattern")
	}))
	defer targetSrv.Close()

	mitm, proxyAddr := startTestProxy(t, nil)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, "http://"+proxyAddr))}}
	resp, err := client.Get(targetSrv.URL + "/leak")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	types := map[string]bool{}
	for _, f := range mitm.Findings() {
		types[f.Type] = true
	}
	if !types["AWS Access Key Exposed"] {
		t.Fatalf("aws key leak not detected: %v", types)
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
