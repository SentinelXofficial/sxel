package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

type MITM struct {
	ca       *CA
	caCert   tls.Certificate
	certMu   sync.Map
	scope    []string
	mu       sync.Mutex
	findings []core.ScanResult
	seen     map[string]bool
	started  time.Time
}

func NewMITM(caDir string, scope []string) (*MITM, error) {
	ca, err := LoadOrCreateCA(caDir)
	if err != nil {
		return nil, err
	}
	caTLS := tls.Certificate{
		Certificate: [][]byte{ca.cert.Raw},
		PrivateKey:  ca.key,
	}
	return &MITM{
		ca:      ca,
		caCert:  caTLS,
		scope:   scope,
		seen:    map[string]bool{},
		started: time.Now(),
	}, nil
}

func (m *MITM) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           m,
		ReadHeaderTimeout: 15 * time.Second,
	}
	return srv.ListenAndServe()
}

func (m *MITM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		m.handleConnect(w, r)
		return
	}
	m.forward(w, r, "")
}

func withDefaultPort(host, scheme string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	port := "80"
	if scheme == "https" {
		port = "443"
	}
	if strings.Contains(host, ":") {
		return "[" + stripPort(host) + "]:" + port
	}
	return host + ":" + port
}

func (m *MITM) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	cert, err := m.ca.CertForHost(host, &m.certMu)
	if err != nil {
		http.Error(w, "MITM cert error", http.StatusInternalServerError)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	buf.Flush()

	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	br := bufio.NewReader(tlsConn)
	for {
		tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = host
		}
		rec := httptest.NewRecorder()
		m.forward(rec, req, "https")
		res := rec.Result()
		resBody, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
		if res.ContentLength >= 0 && int64(len(resBody)) < res.ContentLength {
			writeRawResponse(tlsConn, 502, "Bad Gateway", nil, nil)
			return
		}
		if err := writeRawResponse(tlsConn, res.StatusCode, res.Status, res.Header, resBody); err != nil {
			return
		}
		if req.Close || strings.EqualFold(res.Header.Get("Connection"), "close") {
			return
		}
	}
}

func writeRawResponse(w io.Writer, code int, status string, hdr http.Header, body []byte) error {
	connHdrs := map[string]bool{}
	for _, v := range hdr.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			connHdrs[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", code, status); err != nil {
		return err
	}
	for k, vs := range hdr {
		lk := strings.ToLower(k)
		if lk == "content-length" || lk == "transfer-encoding" || isHopByHop(lk) || connHdrs[lk] {
			continue
		}
		for _, v := range vs {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", k, v); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

func isHopByHop(lk string) bool {
	switch lk {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "upgrade":
		return true
	}
	return false
}

func (m *MITM) forward(w http.ResponseWriter, r *http.Request, forcedScheme string) {
	scheme := forcedScheme
	if scheme == "" {
		scheme = r.URL.Scheme
	}
	if scheme == "" {
		scheme = "http"
	}
	upstreamHost := r.URL.Host
	if upstreamHost == "" {
		upstreamHost = r.Host
	}
	upstream := withDefaultPort(upstreamHost, scheme)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", upstream, &tls.Config{ServerName: stripPort(upstreamHost), InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	} else {
		conn, err = dialer.Dial("tcp", upstream)
	}
	if err != nil {
		http.Error(w, "upstream dial failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.URL.Scheme = "http"
	req.URL.Host = upstreamHost
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if err := req.Write(conn); err != nil {
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		http.Error(w, "upstream read failed", http.StatusBadGateway)
		return
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	resp.Body.Close()
	if rerr != nil {
		http.Error(w, "upstream body read failed", http.StatusBadGateway)
		return
	}
	if resp.ContentLength >= 0 && int64(len(body)) < resp.ContentLength {
		http.Error(w, "upstream body exceeds size limit", http.StatusBadGateway)
		return
	}
	resp.Header.Del("Content-Length")
	resp.Header.Del("Transfer-Encoding")
	w.Header()["Content-Length"] = []string{fmt.Sprintf("%d", len(body))}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, werr := w.Write(body); werr != nil {
		return
	}
	m.analyze(r, resp, body)
}

func (m *MITM) analyze(req *http.Request, resp *http.Response, body []byte) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if !m.inScope(host) {
		return
	}
	now := time.Now()
	var found []core.ScanResult
	add := func(f core.ScanResult) {
		key := f.Type + "|" + host + "|" + f.Evidence
		m.mu.Lock()
		if !m.seen[key] {
			m.seen[key] = true
			f.Timestamp = now
			found = append(found, f)
		}
		m.mu.Unlock()
	}
	m.analyzeHeaders(host, req, resp, add)
	m.analyzeCookies(host, resp, add)
	m.analyzeBody(host, req, body, add)
	m.mu.Lock()
	m.findings = append(m.findings, found...)
	m.mu.Unlock()
}

func (m *MITM) analyzeHeaders(host string, req *http.Request, resp *http.Response, add func(core.ScanResult)) {
	low := map[string]string{}
	for k, vs := range resp.Header {
		low[strings.ToLower(k)] = strings.Join(vs, ",")
	}
	for _, h := range []struct{ name, detail, sev string }{
		{"content-security-policy", "CSP missing", "MEDIUM"},
		{"strict-transport-security", "HSTS missing", "LOW"},
		{"x-frame-options", "X-Frame-Options missing (clickjacking)", "MEDIUM"},
		{"x-content-type-options", "X-Content-Type-Options missing (sniffing)", "LOW"},
		{"referrer-policy", "Referrer-Policy missing", "LOW"},
		{"permissions-policy", "Permissions-Policy missing", "LOW"},
	} {
		if _, ok := low[h.name]; !ok {
			add(core.ScanResult{
				Type: "Missing Security Header", URL: host, Method: req.Method,
				Parameter: h.name, Severity: h.sev, Evidence: h.detail,
			})
		}
	}
}

func (m *MITM) analyzeCookies(host string, resp *http.Response, add func(core.ScanResult)) {
	for _, sc := range resp.Header["Set-Cookie"] {
		name := strings.SplitN(sc, "=", 2)[0]
		flags := strings.ToLower(sc)
		if !strings.Contains(flags, "httponly") {
			add(core.ScanResult{
				Type: "Cookie Missing HttpOnly", URL: host, Method: "SET-COOKIE",
				Parameter: name, Severity: "LOW", Evidence: "HttpOnly flag absent",
			})
		}
		if !strings.Contains(flags, "secure") {
			add(core.ScanResult{
				Type: "Cookie Missing Secure", URL: host, Method: "SET-COOKIE",
				Parameter: name, Severity: "LOW", Evidence: "Secure flag absent",
			})
		}
		if !strings.Contains(flags, "samesite") {
			add(core.ScanResult{
				Type: "Cookie Missing SameSite", URL: host, Method: "SET-COOKIE",
				Parameter: name, Severity: "LOW", Evidence: "SameSite attribute absent",
			})
		}
	}
}

func (m *MITM) analyzeBody(host string, req *http.Request, body []byte, add func(core.ScanResult)) {
	if len(body) > 4<<20 {
		body = body[:4<<20]
	}
	if awsKeyRe.Match(body) {
		add(core.ScanResult{
			Type: "AWS Access Key Exposed", URL: host, Method: req.Method,
			Parameter: "response-body", Severity: "HIGH",
			Evidence: "AWS access key pattern (AKIA...) in response body",
		})
	}
	if privKeyRe.Match(body) {
		add(core.ScanResult{
			Type: "Private Key Exposed", URL: host, Method: req.Method,
			Parameter: "response-body", Severity: "HIGH",
			Evidence: "private key block in response body",
		})
	}
	if pwRe.Match(body) {
		add(core.ScanResult{
			Type: "Credential Pattern in Response", URL: host, Method: req.Method,
			Parameter: "response-body", Severity: "MEDIUM",
			Evidence: "password/secret assignment visible in response body",
		})
	}
}

func (m *MITM) inScope(host string) bool {
	h := strings.ToLower(stripPort(host))
	if len(m.scope) == 0 {
		return true
	}
	for _, s := range m.scope {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if h == s || strings.HasSuffix(h, "."+s) || strings.HasSuffix(h, ":"+s) {
			return true
		}
	}
	return false
}

func (m *MITM) Findings() []core.ScanResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]core.ScanResult, len(m.findings))
	copy(out, m.findings)
	return out
}

func (m *MITM) Summary() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := map[string]int{}
	for _, f := range m.findings {
		counts[f.Severity]++
	}
	return fmt.Sprintf("proxy up %s — findings: %d (critical=%d high=%d medium=%d low=%d info=%d)",
		time.Since(m.started).Round(time.Second),
		len(m.findings), counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"])
}

func (m *MITM) Shutdown(ctx context.Context) error {
	return nil
}

var _ = output.Info
