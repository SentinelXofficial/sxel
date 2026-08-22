package modules

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func ScanGrpc(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

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

	baseURL := strings.TrimRight(core.StripQuery(target.URL), "/")
	for _, path := range grpcGatewayPaths {
		testURL := baseURL + path
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

		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if (resp.StatusCode == 200 || resp.StatusCode == 405) && strings.Contains(ct, "application/json") {
			grpcIndicators := []string{
				"grpc-gateway",
				"google.rpc",
				"protobuf",
				"grpc_gateway",
			}
			for _, indicator := range grpcIndicators {
				if strings.Contains(bodyLow, indicator) {
					results = append(results, core.ScanResult{
						Type:      "gRPC Gateway Endpoint Exposed",
						URL:       testURL,
						Method:    "GET",
						Parameter: "path",
						Payload:   path,
						Severity:  "MEDIUM",
						Evidence:  fmt.Sprintf("gRPC gateway indicator %q found (HTTP %d, content-type %s)", indicator, resp.StatusCode, ct),
						Timestamp: time.Now(),
					})
					break
				}
			}
		}
	}

	grpcPorts := []string{":50051", ":9090"}
	if u, err := url.Parse(target.URL); err == nil && u.Port() != "" {
		own := ":" + u.Port()
		if own != ":50051" && own != ":9090" {
			grpcPorts = append(grpcPorts, own)
		}
	}
	for _, port := range grpcPorts {
		conn, err := net.DialTimeout("tcp", host+port, 2*time.Second)
		if err != nil {
			continue
		}
		preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte(preface)); err != nil {
			conn.Close()
			continue
		}
		buf := make([]byte, 128)
		n, _ := conn.Read(buf)
		conn.Close()
		if n <= 0 {
			continue
		}
		reply := buf[:n]
		h2 := strings.Contains(string(reply), "HTTP/2")
		if !h2 && n >= 4 && reply[0] == 0 && reply[1] == 0 && reply[2] == 0 && reply[3] == 0x04 {
			h2 = true
		}
		if !h2 {
			continue
		}
		results = append(results, core.ScanResult{
			Type:      "gRPC Port Open",
			URL:       fmt.Sprintf("%s:%s", host, port),
			Method:    "TCP",
			Parameter: "port",
			Payload:   port,
			Severity:  "INFO",
			Evidence:  fmt.Sprintf("gRPC port %s on %s answered with the HTTP/2 connection preface", port, host),
			Timestamp: time.Now(),
		})
	}

	return results
}

func extractHostFromURL(rawURL string) string {
	if strings.Contains(rawURL, "://") {
		parts := strings.SplitN(rawURL, "://", 2)
		if len(parts) == 2 {
			host := strings.SplitN(parts[1], "/", 2)[0]
			return hostnameOnly(host)
		}
	}
	return rawURL
}
