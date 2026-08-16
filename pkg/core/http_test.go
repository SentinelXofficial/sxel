package core

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

func TestNewHTTPClientRetriesTooManyRequests(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	cfg := &Config{Timeout: 5}
	client := NewHTTPClient(cfg)

	body, status, err := DoGET(client, cfg, srv.URL)
	if err != nil {
		t.Fatalf("DoGET returned error: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected status 200 after retries, got %d (calls=%d)", status, calls)
	}
	if body != "ok" {
		t.Errorf("expected body %q, got %q", "ok", body)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected 3 attempts (2 failed + 1 success), got %d", got)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCountingTransportBrotli(t *testing.T) {
	original := "hello brotli world — 你好，世界"

	var compressed bytes.Buffer
	bw := brotli.NewWriter(&compressed)
	if _, err := bw.Write([]byte(original)); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}

	stub := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Encoding": []string{"br"}},
			Body:          io.NopCloser(&compressed),
			ContentLength: int64(compressed.Len()),
		}, nil
	})

	var sent, failed, totalNS int64
	ct := &CountingTransport{Base: stub, Sent: &sent, Failed: &failed, TotalNS: &totalNS}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp, err := ct.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading decompressed body: %v", err)
	}
	if string(got) != original {
		t.Errorf("decompressed body mismatch:\n got %q\nwant %q", string(got), original)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("expected Content-Encoding removed, got %q", enc)
	}
	if sent != 1 {
		t.Errorf("expected Sent counter == 1, got %d", sent)
	}
	if failed != 0 {
		t.Errorf("expected Failed counter == 0, got %d", failed)
	}
	if totalNS <= 0 {
		t.Errorf("expected TotalNS counter > 0, got %d", totalNS)
	}
}

func TestCountingTransportNotBrotli(t *testing.T) {
	body := "plain text"
	stub := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Encoding": []string{"gzip"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})

	var sent, failed, totalNS int64
	ct := &CountingTransport{Base: stub, Sent: &sent, Failed: &failed, TotalNS: &totalNS}

	resp, err := ct.RoundTrip(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Errorf("expected body %q, got %q", body, string(got))
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("expected Content-Encoding %q, got %q", "gzip", enc)
	}
}

func TestCountingTransportError(t *testing.T) {
	boom := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})

	var sent, failed, totalNS int64
	ct := &CountingTransport{Base: boom, Sent: &sent, Failed: &failed, TotalNS: &totalNS}

	_, err := ct.RoundTrip(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if err == nil {
		t.Fatal("expected RoundTrip to propagate error")
	}
	if sent != 1 || failed != 1 {
		t.Errorf("expected Sent=1 Failed=1, got Sent=%d Failed=%d", sent, failed)
	}
}

func TestRateLimiterNilWait(t *testing.T) {
	var rl *RateLimiter
	rl.Wait()
	rl.Close()
}

func TestRateLimiterBurst(t *testing.T) {
	rl := NewRateLimiter(1000)
	start := time.Now()
	for i := 0; i < 5; i++ {
		rl.Wait()
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("5 Wait() calls on a 1000 rps limiter took %v (unexpectedly slow)", elapsed)
	}
	rl.Close()
}

func TestRateLimiterDefensiveZero(t *testing.T) {
	rl := NewRateLimiter(0)
	start := time.Now()
	rl.Wait()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("first Wait() on fresh limiter took %v (should be immediate)", elapsed)
	}
	rl.Close()
}
