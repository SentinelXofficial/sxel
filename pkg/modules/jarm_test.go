package modules

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestScanJARM(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	cfg := &core.Config{}
	findings := ScanJARM(srv.Client(), cfg, srv.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 JARM finding, got %d", len(findings))
	}
	h := findings[0].Payload
	if len(h) != 62 {
		t.Errorf("JARM hash must be 62 chars, got %d (%q)", len(h), h)
	}
	if strings.Trim(h, "0") == "" {
		t.Errorf("hash must not be all zeros: %q", h)
	}
}

func TestScanJARMUnreachable(t *testing.T) {
	cfg := &core.Config{}
	findings := ScanJARM(nil, cfg, "http://127.0.0.1:1/")
	if len(findings) != 0 {
		t.Errorf("unreachable host must not produce findings, got %v", findings)
	}
}
