package modules

import (
	"github.com/SentinelXofficial/sxel/pkg/payload"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"github.com/gorilla/websocket"
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
			fmt.Printf("  \033[90m[ws] no endpoints found at %s\033[0m\n", pageURL)
		}
		return results
	}
	fmt.Printf("  \033[36m[ws] %d WebSocket endpoint(s) found\033[0m\n", len(wsURLs))

	dialer := websocket.Dialer{
		HandshakeTimeout: time.Duration(cfg.Timeout) * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	}
	hdr := http.Header{"User-Agent": {cfg.UserAgent}}
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
				fmt.Printf("    \033[90m[ws] dial error: %v\033[0m\n", err)
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
				fmt.Printf("  \033[31m[✗ WS-SQLI]\033[0m %s payload=%q\n", wsURL, pl)
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
				fmt.Printf("  \033[33m[✗ WS-XSS]\033[0m %s payload=%q\n", wsURL, pl)
				break XSSWS
			}
		}
		conn.Close()
	}
	return results
}
