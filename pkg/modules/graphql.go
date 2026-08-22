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

func ScanGraphQL(client *http.Client, cfg *core.Config, baseURL string) []core.ScanResult {
	var results []core.ScanResult

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	origin := base.Scheme + "://" + base.Host

	var endpoints []string
	for _, path := range graphqlPaths {
		ep := origin + path
		body, status, err := gqlPostQuery(client, cfg, ep, `{ __typename }`)
		if err != nil {
			continue
		}
		if gqlEndpointConfirmed(body, status) {
			endpoints = append(endpoints, ep)
			fmt.Printf("  [GRAPHQL] Active endpoint: %s\n", ep)
		}
	}

	if len(endpoints) == 0 {
		return nil
	}

	for _, ep := range endpoints {

		introQuery := `{
  __schema {
    queryType { name }
    types { name kind description }
    mutationType { name }
  }
}`
		introBody, introStatus, err := gqlPostQuery(client, cfg, ep, introQuery)
		// Hardened servers return HTTP 200 with an errors array that may
		// echo the query text — require real schema data, not just the
		// literal "__schema" string anywhere in the body.
		if err == nil && introStatus == 200 && gqlHasSchemaData(introBody) {
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

		deepQuery := gqlBuildDeepQuery(12)
		deepBody, deepStatus, err := gqlPostQuery(client, cfg, ep, deepQuery)
		if err == nil && deepStatus == 200 && strings.Contains(strings.ToLower(deepBody), `"data"`) {
			low := strings.ToLower(deepBody)
			if !strings.Contains(low, "max depth") &&
				!strings.Contains(low, "too deep") &&
				!strings.Contains(low, "maximum depth") &&
				!strings.Contains(low, "complexity") &&
				!strings.Contains(low, "limit") {
				results = append(results, core.ScanResult{
					Type:      "GraphQL Query Depth Limit Not Enforced",
					URL:       ep,
					Method:    "POST",
					Parameter: "query",
					Payload:   deepQuery,
					Severity:  "LOW",
					Evidence:  fmt.Sprintf("Server accepted a %d-level nested query (HTTP %d) without depth rejection", 12, deepStatus),
					Timestamp: time.Now(),
				})
			}
		}

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

// gqlHasSchemaData verifies the response contains actual introspection schema
// payload (data.__schema with queryType/types), not merely the echoed query or
// an error message quoting it.
func gqlHasSchemaData(body string) bool {
	var parsed struct {
		Data struct {
			Schema *struct {
				QueryType    *json.RawMessage  `json:"queryType"`
				MutationType *json.RawMessage  `json:"mutationType"`
				Types        []json.RawMessage `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return false
	}
	s := parsed.Data.Schema
	if s == nil {
		return false
	}
	return s.QueryType != nil || s.MutationType != nil || len(s.Types) > 0
}

func gqlEndpointConfirmed(body string, status int) bool {
	if status != 200 {
		return false
	}
	low := strings.ToLower(body)
	if strings.Contains(low, `"data"`) && strings.Contains(low, "__typename") {
		return true
	}
	return strings.Contains(low, `"errors"`) &&
		(strings.Contains(low, "must provide") || strings.Contains(low, "graphql"))
}

func gqlPostQuery(client *http.Client, cfg *core.Config, endpoint, query string) (string, int, error) {
	payload := map[string]interface{}{"query": query}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}
	return gqlPostRaw(client, cfg, endpoint, data)
}

func gqlPostRaw(client *http.Client, cfg *core.Config, endpoint string, body []byte) (string, int, error) {
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

func gqlBuildDeepQuery(depth int) string {
	var b strings.Builder
	b.WriteString("{ __schema { types { fields { type { name")
	for i := 0; i < depth; i++ {
		b.WriteString(" ofType { name")
	}
	for i := 0; i <= depth; i++ {
		b.WriteString(" }")
	}
	b.WriteString(" } } } }")
	return b.String()
}

func gqlBuildAliasQuery(n int) string {
	var b strings.Builder
	b.WriteString("{ ")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "alias%d: __typename ", i)
	}
	b.WriteString("}")
	return b.String()
}
