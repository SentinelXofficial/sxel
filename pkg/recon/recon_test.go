package recon

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMMH3KnownVectors(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"", 0},
		{"foo", 4138058784},
		{"hello", 613153351},
		{"aaaa", 2129582471},
		{"aaaaaaaaaa", 3246374134},
	}
	for _, c := range cases {
		got := MMH3([]byte(c.in))
		if got != c.want {
			t.Errorf("mmh3(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestFaviconHashBytes(t *testing.T) {
	body := []byte("\x00\x01\x02\x03\x04icon\xff\xfe")
	if h := FaviconHashBytes(body); h == 0 {
		t.Error("non-empty favicon hash should not be 0")
	}
	if h := FaviconHashBytes(nil); h != 0 {
		t.Errorf("empty favicon hash = %d, want 0", h)
	}
}

func TestDetectTech(t *testing.T) {
	body := `<html><head><meta name="generator" content="WordPress 6.4"><script src="/wp-includes/js/jquery.js"></script></head><body><div id="app"></div></body></html>`
	hdr := http.Header{}
	hdr.Set("Server", "nginx/1.24.0")
	hdr.Set("X-Powered-By", "PHP/8.2")
	hdr.Set("X-AspNet-Version", "4.0")
	tech := detectTech(body, hdr)
	joined := strings.Join(tech, ",")
	for _, want := range []string{"wordpress", "jquery", "nginx", "php"} {
		if !strings.Contains(joined, want) {
			t.Errorf("tech detection missing %q; got %v", want, tech)
		}
	}
}

func TestExtractTitle(t *testing.T) {
	body := `<html><head><title>  Hello   &amp;  World </title></head></html>`
	got := extractTitle(body)
	if got != "Hello & World" {
		t.Errorf("extractTitle = %q", got)
	}
}

func TestProbeHostTitleUnescapes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<html><title>Admin &amp; Dashboard</title></html>`)
	}))
	defer srv.Close()
	lh, err := ProbeHost(&http.Client{}, srv.URL, "a", false)
	if err != nil {
		t.Fatal(err)
	}
	if lh.Title != "Admin & Dashboard" {
		t.Errorf("title = %q", lh.Title)
	}
}

func TestPortOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	parts := strings.SplitN(host, ":", 2)
	port := atoiParts(parts[1])
	if !PortOpen(parts[0], port, 3*time.Second) {
		t.Errorf("port %d on %s should be open", port, parts[0])
	}
	if PortOpen(parts[0], 1, 2*time.Second) {
		t.Error("port 1 should be closed")
	}
}

func atoiParts(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func TestProbeHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			w.Write([]byte("icon"))
			return
		}
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Powered-By", "Express")
		io.WriteString(w, "<html><title>Probe Title</title></html>")
	}))
	defer srv.Close()
	client := &http.Client{}
	lh, err := ProbeHost(client, srv.URL, "test-agent", false)
	if err != nil {
		t.Fatal(err)
	}
	if lh.Status != 200 || lh.Title != "Probe Title" || lh.Server != "TestServer/1.0" {
		t.Errorf("unexpected probe result: %+v", lh)
	}
	if !strings.Contains(strings.Join(lh.Tech, ","), "express") {
		t.Errorf("express not detected: %+v", lh.Tech)
	}
}

func TestProbeHostFavicon(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("icon"))
	}))
	defer srv.Close()
	client := &http.Client{}
	lh, err := ProbeHost(client, srv.URL, "a", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(lh.Favicon, "favicon-hash:") {
		t.Errorf("favicon hash missing: %+v", lh)
	}
}

func TestHostFromTarget(t *testing.T) {
	cases := map[string]string{
		"https://example.com/path?q=1":  "example.com",
		"http://sub.example.com:8080/x": "sub.example.com",
		"example.com":                   "example.com",
	}
	for in, want := range cases {
		if got := HostFromTarget(in); got != want {
			t.Errorf("HostFromTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanNames(t *testing.T) {
	names := []string{"www.example.com.", "*.api.example.com", "other.org", "API.Example.COM", "example.com"}
	got := cleanNames(names, "example.com")
	joined := strings.Join(got, ",")
	for _, want := range []string{"www.example.com", "api.example.com", "example.com"} {
		if !strings.Contains(joined, want) {
			t.Errorf("cleanNames missing %q; got %v", want, got)
		}
	}
	if strings.Contains(joined, "other.org") {
		t.Error("out-of-domain name leaked")
	}
}

func TestRunLocalEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Write([]byte("ico"))
			return
		}
		w.Header().Set("X-Powered-By", "Express")
		io.WriteString(w, "<html><title>Local Recon</title></html>")
	}))
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(Options{
		Target:      host,
		Ports:       []int{atoiParts(portStr)},
		Timeout:     5 * time.Second,
		Concurrency: 5,
		UserAgent:   "recon-test",
		Probe:       true,
		Favicon:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Live) != 1 {
		t.Fatalf("expected 1 live host, got %+v", res.Live)
	}
	lh := res.Live[0]
	if lh.Status != 200 || lh.Title != "Local Recon" {
		t.Errorf("unexpected live host: %+v", lh)
	}
	if lh.Favicon == "" {
		t.Error("favicon hash missing")
	}
	if !strings.Contains(strings.Join(lh.Tech, ","), "express") {
		t.Errorf("tech not detected: %+v", lh.Tech)
	}
}

func TestRunSkipsPassiveForIP(t *testing.T) {
	res, err := Run(Options{
		Target:      "127.0.0.1",
		Ports:       []int{1},
		Timeout:     2 * time.Second,
		Concurrency: 2,
		Probe:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Subdomains) != 0 {
		t.Errorf("IP target should skip passive, got %v", res.Subdomains)
	}
	if len(res.Live) != 0 {
		t.Errorf("no live hosts expected, got %v", res.Live)
	}
}
