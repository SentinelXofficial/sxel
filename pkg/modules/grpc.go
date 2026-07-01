package modules

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

// ScanGrpc probes for gRPC reflection and REST gateway endpoints.
func ScanGrpc(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// ── gRPC REST gateway paths ─────────────────────────────────────────────
	grpcGatewayPaths := []string{
		"/v1/",
		"/v2/",
		"/api/v1/",
		"/api/v2/",
		"/grpc/",
		"/swagger/",
		"/swagger.json",
		"/openapi.json",
	}

	host := extractHostFromURL(target.URL)

	for _, path := range grpcGatewayPaths {
		testURL := target.URL + path
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(req, cfg)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body := core.ReadBody(resp.Body)
		resp.Body.Close()

		bodyLow := strings.ToLower(body)

		// gRPC gateway exposes REST endpoints with specific JSON patterns
		if resp.StatusCode == 200 || resp.StatusCode == 405 {
			grpcIndicators := []string{
				`"grpc-gateway"`,
				`"swagger"`,
				`"openapi"`,
				`"paths"`,
				`"definitions"`,
				`"x-google-backend"`,
				`"google.api.http"`,
			}
			for _, indicator := range grpcIndicators {
				if strings.Contains(bodyLow, strings.ToLower(indicator)) {
					results = append(results, core.ScanResult{
						Type:      "gRPC Gateway Endpoint Exposed",
						URL:       testURL,
						Method:    "GET",
						Parameter: "path",
						Payload:   path,
						Severity:  "MEDIUM",
						Evidence:  fmt.Sprintf("gRPC gateway indicator %q found (HTTP %d)", indicator, resp.StatusCode),
						Timestamp: time.Now(),
					})
					break
				}
			}
		}
	}

	// ── gRPC reflection check (TCP) ──────────────────────────────────────────
	// gRPC reflection uses HTTP/2 on the same port or port+1
	if resp, err := http.Get(fmt.Sprintf("http://%s:50051/", host)); err == nil {
		resp.Body.Close()
	}

	// Try common gRPC ports via TCP
	grpcPorts := []string{":50051", ":9090", ":8080"}
	for _, port := range grpcPorts {
		conn, err := net.DialTimeout("tcp", host+port, 2*time.Second)
		if err == nil {
			conn.Close()
			results = append(results, core.ScanResult{
				Type:      "gRPC Port Open",
				URL:       fmt.Sprintf("%s:%s", host, port),
				Method:    "TCP",
				Parameter: "port",
				Payload:   port,
				Severity:  "INFO",
				Evidence:  fmt.Sprintf("gRPC common port %s is open on %s", port, host),
				Timestamp: time.Now(),
			})
		}
	}

	return results
}

func extractHostFromURL(rawURL string) string {
	if strings.Contains(rawURL, "://") {
		parts := strings.SplitN(rawURL, "://", 2)
		if len(parts) == 2 {
			host := strings.SplitN(parts[1], "/", 2)[0]
			return strings.SplitN(host, ":", 2)[0]
		}
	}
	return rawURL
}
