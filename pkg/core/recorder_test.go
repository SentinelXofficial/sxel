package core

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRecorderCaptureAndMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Probe", "yes")
		io.WriteString(w, "hello world")
	}))
	defer srv.Close()

	rec := NewRecorder(64)
	cfg := &Config{Recorder: rec}
	client := NewHTTPClient(cfg)

	body, status, err := DoGET(client, cfg, srv.URL+"?x=1")
	if err != nil || status != 200 || body != "hello world" {
		t.Fatalf("doGET: status=%d err=%v", status, err)
	}

	ex := rec.Match("GET", srv.URL+"?x=1")
	if ex == nil {
		t.Fatal("no matching exchange recorded")
	}
	if !strings.Contains(ex.Request, "GET /?x=1 HTTP/1.1") {
		t.Fatalf("request dump missing request line: %q", ex.Request)
	}
	if !strings.Contains(ex.Response, "X-Probe: yes") || !strings.Contains(ex.Response, "hello world") {
		t.Fatalf("response dump incomplete: %q", ex.Response)
	}
	if ex.Status != 200 {
		t.Fatalf("status: %d", ex.Status)
	}
}

func TestRecorderMatchFallbackPath(t *testing.T) {
	rec := NewRecorder(8)
	rec.Add(Exchange{Method: "POST", URL: "http://h.test/submit", Request: "req", Response: "resp", Status: 200})
	ex := rec.Match("POST", "http://h.test/submit")
	if ex == nil || ex.Request != "req" {
		t.Fatalf("exact match failed: %+v", ex)
	}
	if rec.Match("GET", "http://h.test/submit") != nil {
		t.Fatal("method mismatch should not match")
	}
	if rec.Match("POST", "http://other.test/submit") != nil {
		t.Fatal("host mismatch should not match")
	}
}

func TestRecorderPostBodyCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rec := NewRecorder(16)
	cfg := &Config{Recorder: rec}
	client := NewHTTPClient(cfg)

	vals := url.Values{"a": []string{"b c"}}
	if _, _, err := DoPOST(client, cfg, srv.URL, vals); err != nil {
		t.Fatal(err)
	}
	ex := rec.Match("POST", srv.URL)
	if ex == nil || !strings.Contains(ex.Request, "a=b+c") {
		t.Fatalf("POST body not captured: %q", ex.Request)
	}
}

func TestRecorderDoesNotTruncateLargeBody(t *testing.T) {
	big := strings.Repeat("A", 20000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, big)
	}))
	defer srv.Close()

	cfg := &Config{Recorder: NewRecorder(16)}
	client := NewHTTPClient(cfg)
	body, _, err := DoGET(client, cfg, srv.URL+"/big")
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 20000 {
		t.Fatalf("scanner body truncated: got %d want 20000", len(body))
	}
	ex := cfg.Recorder.Match("GET", srv.URL+"/big")
	if ex == nil || len(ex.Response) > 9000 {
		t.Fatalf("evidence dump should stay bounded, got %d", len(ex.Response))
	}
}
