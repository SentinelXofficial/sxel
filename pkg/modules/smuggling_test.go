package modules

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

type rawBackend struct {
	ln net.Listener
}

func (b *rawBackend) addr() string {
	return b.ln.Addr().String()
}

func (b *rawBackend) close() {
	b.ln.Close()
}

func serveRaw(framing string, handler func(c net.Conn, br *bufio.Reader, reqLine string, headers map[string]string, body string)) *rawBackend {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	b := &rawBackend{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					reqLine, err := br.ReadString('\n')
					if err != nil {
						return
					}
					reqLine = strings.TrimRight(reqLine, "\r\n")
					headers := map[string]string{}
					for {
						line, err := br.ReadString('\n')
						if err != nil {
							return
						}
						line = strings.TrimRight(line, "\r\n")
						if line == "" {
							break
						}
						parts := strings.SplitN(line, ":", 2)
						if len(parts) == 2 {
							headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
						}
					}
					body := ""
					if framing == "te" && strings.EqualFold(headers["transfer-encoding"], "chunked") {
						for {
							line, err := br.ReadString('\n')
							if err != nil {
								return
							}
							line = strings.TrimRight(line, "\r\n")
							size, _ := strconv.ParseInt(line, 16, 32)
							if size == 0 {
								br.ReadString('\n')
								break
							}
							chunk := make([]byte, size)
							total := 0
							for total < int(size) {
								n, err := br.Read(chunk[total:])
								if err != nil {
									return
								}
								total += n
							}
							br.ReadString('\n')
						}
					} else if cl, ok := headers["content-length"]; ok {
						n, _ := strconv.Atoi(cl)
						buf := make([]byte, n)
						total := 0
						for total < n {
							read, err := br.Read(buf[total:])
							if err != nil {
								return
							}
							total += read
						}
						body = string(buf)
					}
					handler(c, br, reqLine, headers, body)
					if strings.EqualFold(headers["connection"], "close") {
						return
					}
				}
			}(conn)
		}
	}()
	return b
}

func writeResp(c net.Conn, status int, body string) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

func TestScanSmugglingSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	cfg := &core.Config{UserAgent: "sxel-test"}
	findings := ScanSmuggling(srv.Client(), cfg, core.CrawlResult{URL: srv.URL})
	if len(findings) != 0 {
		t.Fatalf("clean stack must not produce smuggling findings, got %+v", findings)
	}
}

func TestScanSmugglingCLTE(t *testing.T) {
	backend := serveRaw("te", func(c net.Conn, br *bufio.Reader, reqLine string, headers map[string]string, body string) {
		writeResp(c, 200, "echo:"+reqLine)
	})
	defer backend.close()

	u := "http://" + backend.addr() + "/x"
	cfg := &core.Config{UserAgent: "sxel-test"}
	findings := ScanSmuggling(&http.Client{}, cfg, core.CrawlResult{URL: u})
	if len(findings) != 1 {
		t.Fatalf("expected 1 CL.TE finding on TE backend, got %+v", findings)
	}
	if !strings.Contains(findings[0].Type, "CL.TE") {
		t.Errorf("expected CL.TE finding, got %q", findings[0].Type)
	}
}

func TestScanSmugglingTECL(t *testing.T) {
	backend := serveRaw("cl", func(c net.Conn, br *bufio.Reader, reqLine string, headers map[string]string, body string) {
		writeResp(c, 200, "echo:"+reqLine)
	})
	defer backend.close()

	u := "http://" + backend.addr() + "/x"
	cfg := &core.Config{UserAgent: "sxel-test"}
	findings := ScanSmuggling(&http.Client{}, cfg, core.CrawlResult{URL: u})
	if len(findings) != 1 {
		t.Fatalf("expected 1 TE.CL finding on CL backend, got %+v", findings)
	}
	if !strings.Contains(findings[0].Type, "TE.CL") {
		t.Errorf("expected TE.CL finding, got %q", findings[0].Type)
	}
}

func TestSmugMarkerRandom(t *testing.T) {
	m1 := smugMarkerPath()
	m2 := smugMarkerPath()
	if m1 == m2 {
		t.Errorf("markers must be unique per call: %s %s", m1, m2)
	}
	if _, err := url.Parse(m1); err != nil {
		t.Errorf("marker must parse as URL path: %v", err)
	}
}
