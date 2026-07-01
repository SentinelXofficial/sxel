package modules

import (
	"crypto/tls"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/payload"
	"github.com/gorilla/websocket"
	"net/http"
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

// ScanWebSocket discovers WS endpoints on a page and probes them for SQLi/XSS
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
	output.Info("[ws] %d WebSocket endpoint(s) found\n", len(wsURLs))

	dialer := websocket.Dialer{
		HandshakeTimeout: time.Duration(cfg.Timeout) * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}
	// Include all user-supplied headers so authenticated WebSocket endpoints
	// (e.g. those behind auth proxies) are reachable.
	hdr := http.Header{"User-Agent": {cfg.UserAgent}}
	for k, v := range cfg.Headers {
		hdr.Set(k, v)
	}
	if cfg.Cookie != "" {
		hdr.Set("Cookie", cfg.Cookie)
	}

	for _, wsURL := range wsURLs {
		cfg.Limiter.Wait() // rate-limit WebSocket connections like HTTP
		fmt.Printf("  → WS: %s\n", wsURL)
		conn, resp, err := dialer.Dial(wsURL, hdr)
		if resp != nil {
			resp.Body.Close()
		}
		if err != nil {
			if cfg.Verbose {
				output.Verbose("[ws] dial error: %v", err)
			}
			continue
		}

		// SQLi probes
		sqPL := payload.SQLiPayloads
		if len(sqPL) > 10 {
			sqPL = sqPL[:10]
		}
	SQLiWS:
		for _, pl := range sqPL {
			cfg.Limiter.Wait()
			if e := conn.WriteMessage(websocket.TextMessage, []byte(pl)); e != nil {
				break
			}
			if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				break
			}
			_, msg, e := conn.ReadMessage()
			if e != nil {
				continue
			}
			if ev := DetectSQLi(string(msg)); ev != "" {
				results = append(results, core.ScanResult{
					Type: "WebSocket SQL Injection", URL: wsURL,
					Method: "WS", Parameter: "message", Payload: pl,
					Severity: "HIGH", Evidence: ev, Timestamp: time.Now(),
				})
				break SQLiWS
			}
		}

		// XSS probes
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
			if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				break
			}
			_, msg, e := conn.ReadMessage()
			if e != nil {
				continue
			}
			if strings.Contains(string(msg), pl) {
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
