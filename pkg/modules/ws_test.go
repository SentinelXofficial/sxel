package modules

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/gorilla/websocket"
)

func startWSTestServer(t *testing.T, handler func(msg []byte) []byte) string {
	t.Helper()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if resp := handler(msg); resp != nil {
				if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
					return
				}
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws://" + strings.TrimPrefix(srv.URL, "http://")
}

func pageWithWS(t *testing.T, wsTarget string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><script>new WebSocket(%q)</script></html>", wsTarget)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sqlEchoHandler(msg []byte) []byte {
	if bytes.Contains(msg, []byte("'")) {
		return []byte("SQL error: you have an error in your sql syntax near '1'")
	}
	return msg
}

func xssEchoHandler(msg []byte) []byte {
	if strings.Contains(string(msg), "sxel-control-hello") {
		return nil
	}
	if bytes.Contains(msg, []byte("<script")) || bytes.Contains(msg, []byte("alert")) {
		return msg
	}
	return nil
}

func TestFindWSURLs(t *testing.T) {
	body := `
<script>new WebSocket("ws://api.example.com/sock")</script>
<script>new WebSocket('wss://api.example.com/secure')</script>
var x = "ws://api.example.com/sock";
var y = "wss://api.example.com/other";
new WebSocket("//rel.example.com/rel");
new WebSocket("/relative/path");
`
	got := findWSURLs(body)
	seen := map[string]bool{}
	for _, u := range got {
		if seen[u] {
			t.Errorf("duplicate URL %q", u)
		}
		seen[u] = true
	}
	for _, want := range []string{
		"ws://api.example.com/sock",
		"wss://api.example.com/secure",
		"wss://api.example.com/other",
		"//rel.example.com/rel",
		"/relative/path",
	} {
		if !seen[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

func TestScanWebSocketSQLi(t *testing.T) {
	wsURL := startWSTestServer(t, sqlEchoHandler)
	page := pageWithWS(t, wsURL)
	cfg := &core.Config{Timeout: 5}
	results := ScanWebSocket(core.NewHTTPClient(cfg), cfg, page.URL)
	if len(results) == 0 {
		t.Fatal("expected SQLi finding, got none")
	}
	if results[0].Type != "WebSocket SQL Injection" {
		t.Errorf("unexpected type %q", results[0].Type)
	}
	if results[0].Severity != "HIGH" {
		t.Errorf("unexpected severity %q", results[0].Severity)
	}
}

func TestScanWebSocketXSS(t *testing.T) {
	wsURL := startWSTestServer(t, xssEchoHandler)
	page := pageWithWS(t, wsURL)
	cfg := &core.Config{Timeout: 5}
	results := ScanWebSocket(core.NewHTTPClient(cfg), cfg, page.URL)
	if len(results) == 0 {
		t.Fatal("expected XSS finding, got none")
	}
	if results[0].Type != "WebSocket XSS" {
		t.Errorf("unexpected type %q", results[0].Type)
	}
}

func TestScanWebSocketNoEndpoints(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>no websockets here</html>"))
	}))
	defer page.Close()
	cfg := &core.Config{Timeout: 5, Verbose: true}
	results := ScanWebSocket(core.NewHTTPClient(cfg), cfg, page.URL)
	if len(results) != 0 {
		t.Errorf("expected no results, got %d", len(results))
	}
}

func TestScanWebSocketProtoRelative(t *testing.T) {
	wsURL := startWSTestServer(t, sqlEchoHandler)
	host := strings.TrimPrefix(wsURL, "ws://")
	page := pageWithWS(t, "//"+host+"/sock")
	cfg := &core.Config{Timeout: 5}
	results := ScanWebSocket(core.NewHTTPClient(cfg), cfg, page.URL)
	if len(results) == 0 {
		t.Fatal("expected SQLi finding via protocol-relative URL, got none")
	}
}

func TestScanWebSocketRelativePath(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	var page *httptest.Server
	page = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sock" {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				_, msg, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if resp := sqlEchoHandler(msg); resp != nil {
					if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
						return
					}
				}
			}
		}
		fmt.Fprintf(w, "<script>new WebSocket(%q)</script>", "/sock")
	}))
	defer page.Close()
	cfg := &core.Config{Timeout: 5}
	results := ScanWebSocket(core.NewHTTPClient(cfg), cfg, page.URL)
	if len(results) == 0 {
		t.Fatal("expected SQLi finding via relative path, got none")
	}
	want := "ws://" + strings.TrimPrefix(page.URL, "http://") + "/sock"
	if results[0].URL != want {
		t.Errorf("unexpected URL %q, want %q", results[0].URL, want)
	}
}

func TestScanWebSocketHTTPSPageUsesWSS(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<script>new WebSocket(%q)</script>", "//"+strings.TrimPrefix(ts.URL, "https://")+"/s")
	}))
	defer ts.Close()
	cfg := &core.Config{Timeout: 5}
	client := core.NewHTTPClient(cfg)
	body, _, err := core.DoGET(client, cfg, ts.URL)
	if err != nil {
		t.Fatalf("page fetch: %v", err)
	}
	found := findWSURLs(body)
	if len(found) == 0 {
		t.Fatal("expected ws candidate from https page")
	}
	if !strings.HasPrefix(found[0], "//") {
		t.Errorf("unexpected candidate %q", found[0])
	}
}
