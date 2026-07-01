package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Common GraphQL endpoint paths to probe when no explicit endpoint is supplied.
var graphqlPaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/v2/graphql",
	"/query",
	"/gql",
	"/graphiql",
	"/playground",
	"/api",
	"/graphql/v1",
	"/graphql/v2",
}

// ScanGraphQL probes common GraphQL endpoints and tests for:
//
//  1. Introspection enabled  — full schema enumerable by attackers
//  2. Field suggestions leak — server hints at real field names
//  3. Query batching attack  — may allow rate-limit bypass / brute-force
//  4. Unbounded query depth  — potential denial-of-service
//  5. Alias amplification    — resource amplification via many aliases
func ScanGraphQL(client *http.Client, cfg *core.Config, baseURL string) []core.ScanResult {
	var results []core.ScanResult

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	origin := base.Scheme + "://" + base.Host

	// ── Discover active GraphQL endpoints ─────────────────────────────────
	var endpoints []string
	for _, path := range graphqlPaths {
		ep := origin + path
		body, status, err := gqlPostQuery(client, cfg, ep, `{ __typename }`)
		if err != nil {
			continue
		}
		low := strings.ToLower(body)
		if status == 200 && (strings.Contains(low, `"data"`) ||
			strings.Contains(low, `"errors"`) ||
			strings.Contains(low, `"__typename"`)) {
			endpoints = append(endpoints, ep)
			fmt.Printf("  [GRAPHQL] Active endpoint: %s\n", ep)
		}
	}

	if len(endpoints) == 0 {
		return nil
	}

	for _, ep := range endpoints {

		// ── Test 1: Introspection ──────────────────────────────────────────
		introQuery := `{
  __schema {
    queryType { name }
    types { name kind description }
    mutationType { name }
  }
}`
		introBody, introStatus, err := gqlPostQuery(client, cfg, ep, introQuery)
		if err == nil && introStatus == 200 && strings.Contains(introBody, `"__schema"`) {
			results = append(results, core.ScanResult{
				Type:      "GraphQL Introspection Enabled",
				URL:       ep,
				Method:    "POST",
				Parameter: "query",
				Payload:   `{ __schema { types { name } } }`,
				Severity:  "MEDIUM",
				Evidence:  "Server returned __schema data — full type system is enumerable by attackers",
				Timestamp: time.Now(),
			})
		}

		// ── Test 2: Field suggestions (schema leak even without introspection) ──
		suggestBody, _, err := gqlPostQuery(client, cfg, ep, `{ definitivelyDoesNotExistField }`)
		if err == nil {
			low := strings.ToLower(suggestBody)
			if strings.Contains(low, "did you mean") || strings.Contains(low, "suggestion") {
				results = append(results, core.ScanResult{
					Type:      "GraphQL Field Suggestions Enabled",
					URL:       ep,
					Method:    "POST",
					Parameter: "query",
					Payload:   `{ definitivelyDoesNotExistField }`,
					Severity:  "LOW",
					Evidence:  `Server returned "did you mean" hint — field names enumerable without introspection`,
					Timestamp: time.Now(),
				})
			}
		}

		// ── Test 3: Batch query attack ─────────────────────────────────────
		batchPayload := []map[string]interface{}{
			{"query": "{ __typename }"},
			{"query": "{ __typename }"},
			{"query": "{ __typename }"},
		}
		batchData, _ := json.Marshal(batchPayload)
		batchBody, batchStatus, err := gqlPostRaw(client, cfg, ep, batchData)
		if err == nil && batchStatus == 200 && strings.HasPrefix(strings.TrimSpace(batchBody), "[") {
			results = append(results, core.ScanResult{
				Type:      "GraphQL Batching Attack Possible",
				URL:       ep,
				Method:    "POST",
				Parameter: "query (batch)",
				Payload:   `[{"query":"..."},{"query":"..."},{"query":"..."}]`,
				Severity:  "MEDIUM",
				Evidence:  "Server accepts batched query arrays — may enable rate-limit bypass or brute-force amplification",
				Timestamp: time.Now(),
			})
		}

		// ── Test 4: Unbounded query depth ──────────────────────────────────
		deepQuery := gqlBuildDeepQuery(12)
		deepBody, deepStatus, err := gqlPostQuery(client, cfg, ep, deepQuery)
		if err == nil && deepStatus == 200 {
			low := strings.ToLower(deepBody)
			if !strings.Contains(low, "max depth") &&
				!strings.Contains(low, "too deep") &&
				!strings.Contains(low, "complexity") &&
				!strings.Contains(low, "limit") {
				results = append(results, core.ScanResult{
					Type:      "GraphQL Query Depth Limit Not Enforced",
					URL:       ep,
					Method:    "POST",
					Parameter: "query",
					Payload:   deepQuery,
					Severity:  "LOW",
					Evidence:  fmt.Sprintf("Server accepted a 12-level nested query (HTTP %d) without depth rejection", deepStatus),
					Timestamp: time.Now(),
				})
			}
		}

		// ── Test 5: Alias amplification ────────────────────────────────────
		aliasQuery := gqlBuildAliasQuery(25)
		aliasBody, aliasStatus, err := gqlPostQuery(client, cfg, ep, aliasQuery)
		if err == nil && aliasStatus == 200 {
			low := strings.ToLower(aliasBody)
			if !strings.Contains(low, "too many") &&
				!strings.Contains(low, "rate limit") &&
				!strings.Contains(low, "complexity") {
				results = append(results, core.ScanResult{
					Type:      "GraphQL Alias-Based Resource Amplification",
					URL:       ep,
					Method:    "POST",
					Parameter: "query",
					Payload:   aliasQuery,
					Severity:  "LOW",
					Evidence:  fmt.Sprintf("Server executed a 25-alias query (HTTP %d) — multiplier amplification possible", aliasStatus),
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// gqlPostQuery wraps a query string in a JSON object and POSTs it.
func gqlPostQuery(client *http.Client, cfg *core.Config, endpoint, query string) (string, int, error) {
	payload := map[string]interface{}{"query": query}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}
	return gqlPostRaw(client, cfg, endpoint, data)
}

// gqlPostRaw sends arbitrary JSON bytes as a GraphQL POST request.
func gqlPostRaw(client *http.Client, cfg *core.Config, endpoint string, body []byte) (string, int, error) {
	cfg.Limiter.Wait()
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	core.ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b := core.ReadBody(resp.Body)
	return b, resp.StatusCode, nil
}

// gqlBuildDeepQuery constructs a deeply nested GraphQL query.
func gqlBuildDeepQuery(depth int) string {
	// Use __typename (which exists on every GraphQL type) instead of "a"
	// to ensure the query actually reaches the depth limit before failing.
	q := "{ __typename"
	for i := 0; i < depth; i++ {
		q += " ... on Query { __typename"
	}
	for i := 0; i <= depth; i++ {
		q += " }"
	}
	return q
}

// gqlBuildAliasQuery creates a query with n aliases for the same field.
func gqlBuildAliasQuery(n int) string {
	var b strings.Builder
	b.WriteString("{ ")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "alias%d: __typename ", i)
	}
	b.WriteString("}")
	return b.String()
}
