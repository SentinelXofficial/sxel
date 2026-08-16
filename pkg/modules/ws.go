package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/payload"
	"github.com/gorilla/websocket"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	wsNewRe = regexp.MustCompile(`(?i)new\s+WebSocket\(\s*["']([^"']+)["']\s*\)`)
	wsRawRe = regexp.MustCompile(`["'](wss?://[^"'\s]+)["']`)
)

func findWSURLs(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range wsNewRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	for _, m := range wsRawRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

func ScanWebSocket(client *http.Client, cfg *core.Config, pageURL string) []core.ScanResult {
	var results []core.ScanResult

	body, _, err := core.DoGET(client, cfg, pageURL)
	if err != nil {
		return results
	}

	wsURLs := findWSURLs(body)
	if len(wsURLs) == 0 {
		if cfg.Verbose {
			output.Verbose("[ws] no endpoints found at %s", pageURL)
		}
		return results
	}

	base, err := url.Parse(pageURL)
	if err != nil {
		return results
	}
	resolved := make([]string, 0, len(wsURLs))
	for _, u := range wsURLs {
		ref, err := url.Parse(u)
		if err != nil {
			continue
		}
		if ref.Scheme == "" && (ref.Host != "" || ref.Path != "") {
			if base.Scheme == "https" || base.Scheme == "wss" {
				ref.Scheme = "wss"
			} else {
				ref.Scheme = "ws"
			}
			if ref.Host == "" {
				ref.Host = base.Host
				ref.User = base.User
			}
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "ws" && abs.Scheme != "wss" {
			continue
		}
		resolved = append(resolved, abs.String())
	}
	if len(resolved) == 0 {
		return results
	}
	output.Info("[ws] %d WebSocket endpoint(s) found\n", len(resolved))

	hdr := http.Header{"User-Agent": {cfg.UserAgent}}
	for k, v := range cfg.Headers {
		hdr.Set(k, v)
	}
	if cfg.Cookie != "" {
		hdr.Set("Cookie", cfg.Cookie)
	}
	dial := func(wsURL string) *websocket.Conn {
		cfg.Limiter.Wait()
		hsTimeout := time.Duration(cfg.Timeout) * time.Second
		if cfg.HandshakeTimeout > 0 {
			hsTimeout = time.Duration(cfg.HandshakeTimeout) * time.Second
		}
		if hsTimeout <= 0 {
			hsTimeout = 10 * time.Second
		}
		dialer := websocket.Dialer{
			HandshakeTimeout: hsTimeout,
			TLSClientConfig:  core.TLSClientConfigFor(cfg),
		}
		conn, resp, err := dialer.Dial(wsURL, hdr)
		if resp != nil {
			resp.Body.Close()
		}
		if err != nil {
			if cfg.Verbose {
				output.Verbose("[ws] dial error: %v", err)
			}
			return nil
		}
		return conn
	}
	readReply := func(conn *websocket.Conn) (string, error) {
		if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return "", err
		}
		_, msg, err := conn.ReadMessage()
		return string(msg), err
	}

	for _, wsURL := range resolved {
		fmt.Printf("  → WS: %s\n", wsURL)
		conn := dial(wsURL)
		if conn == nil {
			continue
		}

		sqPL := payload.SQLiPayloads
		if len(sqPL) > 10 {
			sqPL = sqPL[:10]
		}
		baselineMsg := ""
		baselineOK := false
		if e := conn.WriteMessage(websocket.TextMessage, []byte("sxel-control-hello")); e == nil {
			if msg, e := readReply(conn); e == nil {
				baselineMsg = msg
				baselineOK = true
			}
		}
	SQLiWS:
		for _, pl := range sqPL {
			cfg.Limiter.Wait()
			if e := conn.WriteMessage(websocket.TextMessage, []byte(pl)); e != nil {
				break
			}
			msg, e := readReply(conn)
			if e != nil {
				break
			}
			if baselineOK && DetectSQLi(baselineMsg) != "" {
				break SQLiWS
			}
			if ev := DetectSQLi(msg); ev != "" {
				results = append(results, core.ScanResult{
					Type: "WebSocket SQL Injection", URL: wsURL,
					Method: "WS", Parameter: "message", Payload: pl,
					Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
				})
				break SQLiWS
			}
		}
		conn.Close()

		conn = dial(wsURL)
		if conn == nil {
			continue
		}
		xsPL := payload.XSSPayloads
		if len(xsPL) > 10 {
			xsPL = xsPL[:10]
		}
	XSSWS:
		for _, pl := range xsPL {
			cfg.Limiter.Wait()
			if e := conn.WriteMessage(websocket.TextMessage, []byte(pl)); e != nil {
				break
			}
			msg, e := readReply(conn)
			if e != nil {
				break
			}
			if strings.Contains(msg, pl) {
				results = append(results, core.ScanResult{
					Type: "WebSocket XSS", URL: wsURL,
					Method: "WS", Parameter: "message", Payload: pl,
					Severity: "MEDIUM", Evidence: "payload reflected in WS response",
					Timestamp: time.Now(),
				})
				break XSSWS
			}
		}
		conn.Close()
	}
	return results
}
