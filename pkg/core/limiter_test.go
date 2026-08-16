package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterTransportThrottlesAllRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	cfg := &Config{}
	cfg.Limiter = NewRateLimiter(5)
	client := NewHTTPClient(cfg)

	if !clientHasLimiter(client.Transport) {
		t.Fatalf("NewHTTPClient transport chain must include limiterTransport")
	}

	start := time.Now()
	for i := 0; i < 12; i++ {
		DoGET(client, cfg, srv.URL)
	}
	elapsed := time.Since(start)
	if elapsed < 1*time.Second {
		t.Errorf("12 requests at 5 rps (burst 5) should take >= ~1.4s, took %v", elapsed)
	}
	if elapsed > 6*time.Second {
		t.Errorf("throttling too aggressive: took %v", elapsed)
	}
}

func clientHasLimiter(rt http.RoundTripper) bool {
	switch tt := rt.(type) {
	case *limiterTransport:
		return true
	case *recorderTransport:
		return clientHasLimiter(tt.rt)
	case *retryTransport:
		if tt.rc != nil && tt.rc.HTTPClient != nil {
			return clientHasLimiter(tt.rc.HTTPClient.Transport)
		}
		return false
	case *CountingTransport:
		return clientHasLimiter(tt.Base)
	default:
		return false
	}
}
