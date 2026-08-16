package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

type scanFunc func(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult

func newCfg() *core.Config {
	return &core.Config{
		Timeout:          10,
		HandshakeTimeout: 5,
		UserAgent:        "sxel-integration-test",
	}
}

func runScan(t *testing.T, srv *httptest.Server, fn scanFunc, target core.CrawlResult) []core.ScanResult {
	t.Helper()
	cfg := newCfg()
	client := &http.Client{Timeout: 10 * time.Second}
	if srv != nil {
		client = srv.Client()
	}
	return fn(client, cfg, target)
}

func assertHasType(t *testing.T, res []core.ScanResult, wantType string) []core.ScanResult {
	t.Helper()
	for _, r := range res {
		if strings.Contains(strings.ToLower(r.Type), strings.ToLower(wantType)) {
			return res
		}
	}
	var types []string
	for _, r := range res {
		types = append(types, fmt.Sprintf("%s (%s)", r.Type, r.Severity))
	}
	t.Fatalf("expected finding %q on vulnerable server, got: %v", wantType, types)
	return nil
}

func assertClean(t *testing.T, res []core.ScanResult) {
	t.Helper()
	if len(res) == 0 {
		return
	}
	var types []string
	for _, r := range res {
		types = append(types, fmt.Sprintf("%s (%s)", r.Type, r.Severity))
	}
	t.Fatalf("false positive: %d finding(s) on safe server: %v", len(res), types)
}
