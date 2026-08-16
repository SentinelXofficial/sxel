package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestDoGETRetriesOn429(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 2 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, "finally ok")
	}))
	defer srv.Close()

	cfg := &Config{}
	cfg.Limiter = NewRateLimiter(50)
	body, status, err := DoGET(srv.Client(), cfg, srv.URL+"/x")
	if err != nil {
		t.Fatalf("DoGET failed after 429s: %v", err)
	}
	if status != 200 || body != "finally ok" {
		t.Errorf("expected 200 ok after retries, got %d %q", status, body)
	}
	if hits.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", hits.Load())
	}
	if cfg.Limiter.lim.Limit() >= 50 || !cfg.Limiter.adapted {
		t.Errorf("limiter should have been slowed down, rate=%v", cfg.Limiter.lim.Limit())
	}
}

func TestDoPOSTRetriesWithBody(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		r.ParseForm()
		if r.Form.Get("q") != "payload" {
			http.Error(w, "body lost", http.StatusBadRequest)
			return
		}
		if hits.Load() <= 2 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, "ok: "+r.Form.Get("q"))
	}))
	defer srv.Close()

	cfg := &Config{}
	cfg.Limiter = NewRateLimiter(50)
	data := url.Values{"q": {"payload"}}
	body, status, err := DoPOST(srv.Client(), cfg, srv.URL+"/go", data)
	if err != nil {
		t.Fatalf("DoPOST failed: %v", err)
	}
	if status != 200 || body != "ok: payload" {
		t.Errorf("body must survive retries, got %d %q", status, body)
	}
}
