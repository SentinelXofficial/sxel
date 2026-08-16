package modules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"gopkg.in/yaml.v3"
)

var apiSpecPaths = []string{
	"/openapi.json", "/openapi.yaml", "/openapi.yml",
	"/swagger.json", "/swagger.yaml", "/swagger.yml",
	"/swagger-ui.html", "/swagger-ui/", "/swagger/index.html",
	"/v2/api-docs", "/v3/api-docs", "/api-docs", "/api-docs/",
	"/api/swagger.json", "/api/v1/swagger.json", "/api/v1/openapi.json",
	"/redoc", "/api/v3/api-docs", "/v1/api-docs",
}

var apiSensitiveHints = []string{
	"admin", "user", "account", "profile", "password", "credential",
	"token", "secret", "key", "session", "billing", "payment", "order",
	"config", "internal", "private", "debug", "backup", "export", "role",
}

func ScanAPISecurity(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	base, err := url.Parse(target.URL)
	if err != nil {
		return results
	}
	basePath := strings.TrimRight(base.Path, "/")

	for _, doc := range apiSpecPaths {
		specURL := base.Scheme + "://" + base.Host + basePath + doc
		req, err := http.NewRequest("GET", specURL, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(req, cfg)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body := core.ReadBody(resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		trimmed := strings.TrimSpace(body)
		if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") &&
			!strings.HasPrefix(trimmed, "swagger:") && !strings.HasPrefix(trimmed, "openapi:") {
			continue
		}

		endpoints := parseAPISpec(body)
		results = append(results, core.ScanResult{
			Type:      "API Specification Exposed",
			URL:       specURL,
			Method:    "GET",
			Parameter: "docs",
			Payload:   doc,
			Severity:  "MEDIUM",
			Evidence:  fmt.Sprintf("API specification %s is publicly accessible (HTTP %d, %d bytes) — %d endpoints disclosed", doc, resp.StatusCode, len(body), len(endpoints)),
			Timestamp: time.Now(),
			Extra: map[string]string{
				"endpoint_count": fmt.Sprintf("%d", len(endpoints)),
				"content_type":   resp.Header.Get("Content-Type"),
			},
		})

		if len(endpoints) > 0 {
			results = append(results, testAPIAuthBypass(client, cfg, base, endpoints)...)
		}
		if cfg.Verbose {
			output.Verbose("[api] spec %s -> %d endpoints", specURL, len(endpoints))
		}
		break
	}

	return results
}

func parseAPISpec(body string) []string {
	var endpoints []string
	seen := map[string]bool{}

	if strings.HasPrefix(strings.TrimSpace(body), "openapi:") || strings.HasPrefix(strings.TrimSpace(body), "swagger:") {
		var spec map[string]interface{}
		if err := yaml.Unmarshal([]byte(body), &spec); err != nil {
			return endpoints
		}
		if paths, ok := spec["paths"].(map[string]interface{}); ok {
			for p := range paths {
				if !seen[p] {
					seen[p] = true
					endpoints = append(endpoints, p)
				}
			}
		}
		return endpoints
	}

	var spec map[string]interface{}
	if err := json.Unmarshal([]byte(body), &spec); err != nil {
		return endpoints
	}
	if paths, ok := spec["paths"].(map[string]interface{}); ok {
		for p := range paths {
			if !seen[p] {
				seen[p] = true
				endpoints = append(endpoints, p)
			}
		}
	}
	return endpoints
}

func testAPIAuthBypass(client *http.Client, cfg *core.Config, base *url.URL, endpoints []string) []core.ScanResult {
	var results []core.ScanResult
	noRedir := &http.Client{
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	checked := 0
	for _, ep := range endpoints {
		if checked >= 12 {
			break
		}
		full := base.Scheme + "://" + base.Host + ep
		lower := strings.ToLower(full)
		sensitive := false
		for _, h := range apiSensitiveHints {
			if strings.Contains(lower, h) {
				sensitive = true
				break
			}
		}
		if !sensitive {
			continue
		}

		req, err := http.NewRequest("GET", full, nil)
		if err != nil {
			continue
		}
		core.ApplyHeaders(req, cfg)
		resp, err := noRedir.Do(req)
		if err != nil {
			continue
		}
		body := core.ReadBody(resp.Body)
		resp.Body.Close()
		checked++

		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			results = append(results, core.ScanResult{
				Type:      "API Endpoint Accessible Without Authentication",
				URL:       full,
				Method:    "GET",
				Parameter: "auth",
				Payload:   "no auth header / cookie",
				Severity:  "HIGH",
				Evidence:  fmt.Sprintf("sensitive endpoint %s returned HTTP %d without authentication — possible broken access control (auth bypass)", full, resp.StatusCode),
				Timestamp: time.Now(),
				Extra: map[string]string{
					"response_length": fmt.Sprintf("%d", len(body)),
					"content_type":    resp.Header.Get("Content-Type"),
				},
			})
		}
	}
	return results
}
