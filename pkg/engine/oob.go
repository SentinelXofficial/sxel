package engine

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

// OOBServer is an out-of-band callback server for detecting blind vulnerabilities.
type OOBServer struct {
	Port      int
	Address   string        // external reachable address (set by user or auto-detected)
	Callbacks map[string]*OOBCallback
	mu        sync.Mutex
	server    *http.Server
	listener  net.Listener
	running   bool
}

// OOBCallback records an incoming OOB interaction.
type OOBCallback struct {
	ID        string
	ProbeID   string    // which probe generated this
	Payload   string    // the injected payload
	VulnType  string    // SSRF, XXE, CMDI, etc.
	TargetURL string
	Method    string
	Headers   map[string]string
	Body      string
	Time      time.Time
}

// OOBProbe represents a single OOB test probe.
type OOBProbe struct {
	ID       string
	Type     string // "ssrf", "xxe", "cmdi", "dns"
	Payload  string // the injection payload with {{OOB_URL}} placeholder
	Target   string // where the payload was injected (URL or parameter)
}

// NewOOBServer creates an OOB callback server on a random available port.
func NewOOBServer() (*OOBServer, error) {
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	// Try to detect a non-loopback address for the callback URL.
	// If the machine has a public/private interface, use that instead of 0.0.0.0
	// so the target can actually reach the scanner.
	callbackAddr := fmt.Sprintf("0.0.0.0:%d", listener.Addr().(*net.TCPAddr).Port)
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			callbackAddr = fmt.Sprintf("%s:%d", ipnet.IP.String(), listener.Addr().(*net.TCPAddr).Port)
			break
		}
	}
	oob := &OOBServer{
		Port:      listener.Addr().(*net.TCPAddr).Port,
		Address:   callbackAddr,
		Callbacks: make(map[string]*OOBCallback),
		listener:  listener,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		oob.handleCallback(w, r)
	})

	oob.server = &http.Server{Handler: mux}
	go func() {
		oob.running = true
		oob.server.Serve(listener) //nolint:errcheck
	}()

	output.Info("OOB Callback server listening on %s", oob.Address)
	return oob, nil
}

func (o *OOBServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/")

	body := core.ReadBody(r.Body)
	r.Body.Close()

	headers := make(map[string]string)
	for k, vals := range r.Header {
		headers[k] = strings.Join(vals, ", ")
	}

	cb := &OOBCallback{
		ID:      id,
		Method:  r.Method,
		Headers: headers,
		Body:    string(body),
		Time:    time.Now(),
	}

	o.mu.Lock()
	if existing, ok := o.Callbacks[id]; ok {
		cb.ProbeID = existing.ProbeID
		cb.Payload = existing.Payload
		cb.VulnType = existing.VulnType
		cb.TargetURL = existing.TargetURL
	}
	o.Callbacks[id] = cb
	o.mu.Unlock()

	output.VulnInline("OOB", "callback received: %s → %s", id, cb.VulnType)
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

// RegisterProbe registers a pending OOB probe and returns a unique marker.
func (o *OOBServer) RegisterProbe(probeType, targetURL, payload string) (string, string) {
	id := randomID(16)
	oobURL := fmt.Sprintf("http://%s/%s", o.Address, id)

	o.mu.Lock()
	o.Callbacks[id] = &OOBCallback{
		ID:        id,
		ProbeID:   id,
		Payload:   strings.ReplaceAll(payload, "{{OOB_URL}}", oobURL),
		VulnType:  probeType,
		TargetURL: targetURL,
	}
	o.mu.Unlock()

	return id, oobURL
}

// HasCallback checks if a callback was received for a given probe ID.
func (o *OOBServer) HasCallback(id string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	cb, ok := o.Callbacks[id]
	return ok && cb.Time.After(time.Time{}) && cb.Method != ""
}

// Close shuts down the OOB server.
func (o *OOBServer) Close() {
	if o.running {
		o.listener.Close()
		o.running = false
	}
}

// ── OOB Scanner ─────────────────────────────────────────────────────────────

// RunOOBProbes sends OOB-based probes for blind vulnerability detection.
// Returns confirmed scan results for any probes that received callbacks.
func RunOOBProbes(client *http.Client, cfg *core.Config, targetURL string, oob *OOBServer) []core.ScanResult {
	var results []core.ScanResult

	probes := []struct {
		Type    string
		URLPart string // appended to target URL
		Payload string
	}{
		// SSRF probes
		{"SSRF", "/fetch?url={{OOB_URL}}", "SSRF via URL parameter"},
		{"SSRF", "/proxy?url={{OOB_URL}}", "SSRF via proxy parameter"},
		{"SSRF", "/api/fetch?target={{OOB_URL}}", "SSRF via API fetch"},
		// CMDI probes
		{"CMDI", "/ping?host=; curl {{OOB_URL}}", "Command injection via ping"},
		{"CMDI", "/exec?cmd=wget {{OOB_URL}}", "Command injection via exec"},
		// XXE probes
		{"XXE", "/upload", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{{OOB_URL}}">]><root>&xxe;</root>`},
	}

	// Use a client that doesn't follow redirects
	noRedir := &http.Client{
		Timeout:       client.Timeout,
		Transport:     client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	for _, probe := range probes {
		id, oobURL := oob.RegisterProbe(probe.Type, targetURL, probe.Payload)
		// Substitute placeholder in both Payload and URLPart
		payload := strings.ReplaceAll(probe.Payload, "{{OOB_URL}}", oobURL)
		urlPart := strings.ReplaceAll(probe.URLPart, "{{OOB_URL}}", oobURL)

		var req *http.Request
		var err error

		if probe.Type == "XXE" {
			req, err = http.NewRequest("POST", targetURL+urlPart, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/xml")
		} else {
			req, err = http.NewRequest("GET", targetURL+urlPart, nil)
			if err != nil {
				continue
			}
		}

		core.ApplyHeaders(req, cfg)
		noRedir.Do(req) //nolint:errcheck

		// Wait briefly for callback
		time.Sleep(200 * time.Millisecond)

		if oob.HasCallback(id) {
			oob.mu.Lock()
			cb := oob.Callbacks[id]
			oob.mu.Unlock()
			results = append(results, core.ScanResult{
				Type:      fmt.Sprintf("OOB %s (Blind Detection)", probe.Type),
				URL:       targetURL,
				Method:    "GET",
				Parameter: "oob_probe",
				Payload:   payload,
				Severity:  "CRITICAL",
				Evidence:  fmt.Sprintf("OOB callback confirmed: %s at %s — %s", id, cb.Time.Format("15:04:05"), probe.Payload),
				Timestamp: time.Now(),
			})
		}
	}

	return results
}

func randomID(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[idx.Int64()]
	}
	return string(b)
}
