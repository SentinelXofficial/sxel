package engine

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"gopkg.in/yaml.v3"
)

// ── YAML Template Schema ─────────────────────────────────────────────────────

// Template represents a parsed YAML scanning template.
type Template struct {
	ID    string      `yaml:"id"`
	Brief TemplateBrief `yaml:"brief"`
	Moves []TemplateMove `yaml:"moves"`
}

// TemplateBrief holds template metadata.
type TemplateBrief struct {
	Title string   `yaml:"title"`
	By    string   `yaml:"by"`
	Level string   `yaml:"level"`
	About string   `yaml:"about"`
	Label []string `yaml:"label,omitempty"`
	Score string   `yaml:"score,omitempty"`
}

// TemplateMove is a single HTTP probe within a template.
type TemplateMove struct {
	Verb  string            `yaml:"verb"`
	To    []string          `yaml:"to"`
	Head  map[string]string `yaml:"head,omitempty"`
	Body  string            `yaml:"body,omitempty"`
	Signs []TemplateSign    `yaml:"signs"`
}

// TemplateSign is a detection condition.
type TemplateSign struct {
	On     string `yaml:"on"`               // "word" or "status"
	Has    []string `yaml:"has,omitempty"`   // keywords for word match
	In     string `yaml:"in,omitempty"`      // "body", "header", "all" (default: "body")
	Need   string `yaml:"need,omitempty"`    // "any" (default) or "all"
	Flip   bool   `yaml:"flip,omitempty"`    // invert match
	Status []int  `yaml:"status,omitempty"`  // expected status codes
}

// ── Template Loading ─────────────────────────────────────────────────────────

// LoadTemplates recursively loads all .yaml templates from a directory.
func LoadTemplates(dir string) ([]Template, error) {
	var templates []Template
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") &&
			!strings.HasSuffix(strings.ToLower(info.Name()), ".yml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		var tmpl Template
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil // skip malformed templates
		}
		if tmpl.ID == "" || len(tmpl.Moves) == 0 {
			return nil // skip invalid templates
		}
		// Default: label parsing from YAML inline string like "[a, b, c]"
		if len(tmpl.Brief.Label) == 1 && strings.Contains(tmpl.Brief.Label[0], ",") {
			raw := tmpl.Brief.Label[0]
			raw = strings.Trim(raw, "[]")
			var parts []string
			for _, p := range strings.Split(raw, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					parts = append(parts, p)
				}
			}
			if len(parts) > 0 {
				tmpl.Brief.Label = parts
			}
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, err
}

// ── Template Runner ──────────────────────────────────────────────────────────

// RunTemplates executes all loaded templates against a target URL.
// Returns scan results for any matched templates.
func RunTemplates(client *http.Client, cfg *core.Config, targetURL string, templates []Template) []core.ScanResult {
	var results []core.ScanResult
	base, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	baseURL := fmt.Sprintf("%s://%s", base.Scheme, base.Host)
	hostname := base.Host

	// Pre-flight: request a bogus path to detect SPA catch-all routing.
	// If the SPA returns the same response for every path, file-exposure
	// templates will false-positive on every request.
	spaBaseline, isSPA := detectSPABaseline(client, cfg, baseURL)

	for _, tmpl := range templates {
		// Skip templates below configured severity threshold
		if !matchMinSeverity(tmpl.Brief.Level, cfg.TemplateSeverity) {
			continue
		}
		for _, move := range tmpl.Moves {
			for _, rawPath := range move.To {
				// Expand template variables
				reqURL := strings.ReplaceAll(rawPath, "{{BaseURL}}", baseURL)
				reqURL = strings.ReplaceAll(reqURL, "{{Hostname}}", hostname)

				// Substitute OOB/interactsh URL if available
				oobURL := cfg.OOBAddress
				if oobURL == "" {
					oobURL = "127.0.0.1:0" // placeholder; OOB server not active
				}
				reqURL = strings.ReplaceAll(reqURL, "{{interactsh-url}}", oobURL)
				reqURL = strings.ReplaceAll(reqURL, "{{OOB_URL}}", oobURL)

				// Substitute placeholders in body too
				reqBody := move.Body
				reqBody = strings.ReplaceAll(reqBody, "{{BaseURL}}", baseURL)
				reqBody = strings.ReplaceAll(reqBody, "{{Hostname}}", hostname)
				reqBody = strings.ReplaceAll(reqBody, "{{interactsh-url}}", oobURL)
				reqBody = strings.ReplaceAll(reqBody, "{{OOB_URL}}", oobURL)

				// Build request
				req, err := http.NewRequest(move.Verb, reqURL, strings.NewReader(reqBody))
				if err != nil {
					continue
				}
				core.ApplyHeaders(req, cfg)
				for k, v := range move.Head {
					// Substitute placeholders in header values
					hv := strings.ReplaceAll(v, "{{BaseURL}}", baseURL)
					hv = strings.ReplaceAll(hv, "{{Hostname}}", hostname)
					hv = strings.ReplaceAll(hv, "{{interactsh-url}}", oobURL)
					hv = strings.ReplaceAll(hv, "{{OOB_URL}}", oobURL)
					req.Header.Set(k, hv)
				}

				// Send
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				bodyStr := core.ReadBody(resp.Body)
				resp.Body.Close()

				// Match signs
				if matchSigns(move.Signs, bodyStr, resp) {
					// SPA guard: skip if response is identical to catch-all baseline
					if isSPA && isSPAFalsePositive(bodyStr, spaBaseline) {
						continue
					}
					sev := mapLevel(tmpl.Brief.Level)
					results = append(results, core.ScanResult{
						Type:      fmt.Sprintf("Template: %s", tmpl.Brief.Title),
						URL:       reqURL,
						Method:    move.Verb,
						Parameter: "template",
						Payload:   tmpl.ID,
						Severity:  sev,
						Evidence:  fmt.Sprintf("Template %q matched — %s", tmpl.ID, tmpl.Brief.About),
						Timestamp: time.Now(),
						Extra: map[string]string{
							"template_id":  tmpl.ID,
							"score":        tmpl.Brief.Score,
						},
					})
					output.VulnInline("TPL", "%s → %s [%s]", tmpl.ID, tmpl.Brief.Title, sev)
					break // one match per move is enough
				}
			}
		}
	}
	return results
}

// RunSingleTemplate runs a single template against a specific URL.
func RunSingleTemplate(client *http.Client, cfg *core.Config, tmpl Template, targetURL string) []core.ScanResult {
	return RunTemplates(client, cfg, targetURL, []Template{tmpl})
}

// ── Sign Matching ────────────────────────────────────────────────────────────

func matchSigns(signs []TemplateSign, body string, resp *http.Response) bool {
	if len(signs) == 0 {
		return false
	}
	for _, sign := range signs {
		if sign.On == "status" {
			if matchStatus(sign, resp) {
				return true
			}
		} else {
			// Default: word matching
			if matchWords(sign, body, resp) {
				return true
			}
		}
	}
	return false
}

func matchStatus(sign TemplateSign, resp *http.Response) bool {
	if len(sign.Status) == 0 {
		return false
	}
	for _, expected := range sign.Status {
		if resp.StatusCode == expected {
			return !sign.Flip
		}
	}
	return sign.Flip
}

func matchWords(sign TemplateSign, body string, resp *http.Response) bool {
	if len(sign.Has) == 0 {
		return false
	}

	scope := sign.In
	if scope == "" {
		scope = "body"
	}

	need := sign.Need
	if need == "" {
		need = "any"
	}

	// Build search corpus
	var corpus string
	switch scope {
	case "body":
		corpus = strings.ToLower(body)
	case "header":
		corpus = flattenHeaders(resp)
	case "all":
		corpus = strings.ToLower(body) + " " + flattenHeaders(resp)
	}

	matched := 0
	for _, keyword := range sign.Has {
		if strings.Contains(corpus, strings.ToLower(keyword)) {
			matched++
			if need == "any" {
				return !sign.Flip
			}
		}
	}

	if need == "all" {
		return (matched == len(sign.Has)) != sign.Flip
	}
	return sign.Flip
}

func flattenHeaders(resp *http.Response) string {
	var parts []string
	for k, vals := range resp.Header {
		for _, v := range vals {
			parts = append(parts, strings.ToLower(k)+": "+strings.ToLower(v))
		}
	}
	return strings.Join(parts, " ")
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// severityRank maps level strings to numeric ranks (higher = more severe).
var severityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
}

// matchMinSeverity returns true if the template level meets or exceeds min.
func matchMinSeverity(level, min string) bool {
	if min == "" || min == "info" {
		return true
	}
	minR := severityRank[strings.ToLower(min)]
	lvlR := severityRank[strings.ToLower(level)]
	if minR == 0 {
		minR = 3 // default: medium
	}
	if lvlR == 0 {
		lvlR = 3 // unknown = medium
	}
	return lvlR >= minR
}

// spaBaseline holds the response from requesting a bogus path, used to
// detect SPA catch-all routing that would cause false positives.
type spaBaseline struct {
	body   string
	length int
	status int
}

// detectSPABaseline requests a random path and returns the response.  If the
// status is 2xx (not 404) this likely indicates an SPA with catch-all routing.
func detectSPABaseline(client *http.Client, cfg *core.Config, baseURL string) (spaBaseline, bool) {
	bogusURL := baseURL + "/sxsc_nonexistent_" + fmt.Sprintf("%d", time.Now().UnixNano()/1000)
	body, status, err := core.DoGET(client, cfg, bogusURL)
	if err != nil || status == 404 || status == 0 {
		return spaBaseline{}, false
	}
	return spaBaseline{body: body, length: len(body), status: status}, status >= 200 && status < 400
}

// isSPAFalsePositive returns true if the response looks like an SPA catch-all
// (similar length + status to the bogus-path baseline), not a real hit.
func isSPAFalsePositive(body string, bl spaBaseline) bool {
	if bl.length == 0 {
		return false
	}
	// Same status code + similar body length (±15%) → SPA catch-all
	diff := len(body) - bl.length
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(bl.length) < 0.15
}

func mapLevel(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return "INFO"
	}
}

// genericLabels are label tags that describe vulnerability classes rather
// than specific vendors or products. Templates whose labels are ALL in this
// set (or empty) are considered "generic" and always run. Any label NOT in
// this set marks the template as vendor/product-specific — it only runs
// when that vendor/product is detected in the target fingerprint.
var genericLabels = map[string]bool{
	"cve": true, "cve2020": true, "cve2021": true, "cve2022": true,
	"cve2023": true, "cve2024": true, "cve2025": true, "cve2026": true,
	"cnvd": true, "cnnvd": true, "cnnvd2020": true, "cnnvd2021": true,
	"xss": true, "sqli": true, "rce": true, "lfi": true, "rfi": true,
	"ssrf": true, "xxe": true, "ssti": true, "cmdi": true, "crlf": true,
	"csrf": true, "idor": true, "redirect": true, "open-redirect": true,
	"traversal": true, "path-traversal": true, "directory-traversal": true,
	"injection": true, "code-injection": true, "command-injection": true,
	"sql-injection": true, "nosqli": true, "blind-sqli": true,
	"file-inclusion": true, "file-upload": true, "unrestricted-file-upload": true,
	"upload": true,
	"bypass": true, "auth-bypass": true, "authentication-bypass": true,
	"disclosure": true, "exposure": true, "information-disclosure": true,
	"info-leak": true, "info": true,
	"misconfig": true, "misconfiguration": true, "default-login": true,
	"panel": true, "exposed-panel": true, "login": true, "detect": true,
	"detection": true, "discovery": true, "fingerprint": true,
	"tech": true, "technology": true, "technologies": true,
	"takeover": true, "subdomain-takeover": true,
	"dos": true, "ddos": true, "race-condition": true,
	"deserialization": true, "deserialize": true, "insecure-deserialization": true,
	"cache": true, "cache-poisoning": true,
	"smuggling": true, "http-smuggling": true, "request-smuggling": true,
	"prototype-pollution": true, "proto-pollution": true,
	"oauth": true, "saml": true, "jwt": true, "jwt-none": true,
	"clickjacking": true, "cors": true, "csp": true, "hsts": true,
	"security": true, "vulnerability": true, "vuln": true,
	"exploit": true, "exploitation": true, "attack": true,
	"critical": true, "high": true, "medium": true, "low": true,
	"oast": true, "dns": true, "http": true, "tcp": true,
	"kev": true, "vkev": true, "fuzzing": true, "fuzz": true,
	"generic": true, "misc": true, "miscellaneous": true,
	"header": true, "headers": true, "cookie": true, "cookies": true,
	"backup": true, "backups": true, "config": true, "configuration": true,
	"debug": true, "error": true, "errors": true,
	"api": true, "graphql": true, "rest": true, "soap": true, "wsdl": true,
	"swagger": true, "openapi": true,
	"json": true, "xml": true, "yaml": true, "yml": true,
	"git": true, "svn": true, "hg": true, "mercurial": true,
	"env": true, "dotenv": true, "environment": true,
	"ssh": true, "ftp": true, "smtp": true, "rdp": true, "snmp": true,
	"database": true, "db": true, "mysql": true, "postgresql": true,
	"mssql": true, "oracle-db": true, "mongodb": true, "redis": true,
	"memcached": true, "elasticsearch": true, "couchdb": true,
	"printer": true, "camera": true, "router": true, "firewall": true,
	"vpn": true, "waf": true, "cdn": true, "load-balancer": true,
	"proxy": true, "reverse-proxy": true,
	"ssl": true, "tls": true, "pki": true, "certificate": true,
}

// FilterTemplatesByTech returns only templates relevant to the detected
// technology stack. Templates whose labels are ALL in the genericLabels set
// (or empty) always pass. Templates with any non-generic label are
// vendor/product-specific and only run when matching tech is detected.
func FilterTemplatesByTech(templates []Template, detectedTech []string) []Template {
	techSet := make(map[string]bool, len(detectedTech))
	for _, t := range detectedTech {
		techSet[strings.ToLower(t)] = true
	}

	var filtered []Template
	for _, tmpl := range templates {
		// Collect vendor/product labels from this template
		var vendorLabels []string
		allGeneric := true
		for _, label := range tmpl.Brief.Label {
			if !genericLabels[strings.ToLower(label)] {
				allGeneric = false
				vendorLabels = append(vendorLabels, strings.ToLower(label))
			}
		}

		if allGeneric {
			// Template only has generic labels — always run
			filtered = append(filtered, tmpl)
			continue
		}

		// Template has vendor-specific labels — check if any match detected tech
		if len(techSet) == 0 {
			continue // no tech detected, skip vendor templates
		}
		for _, vl := range vendorLabels {
			if techSet[vl] || techMatchesLabel(techSet, vl) {
				filtered = append(filtered, tmpl)
				break
			}
		}
	}
	return filtered
}

// techMatchesLabel checks if a vendor label loosely matches any detected tech.
func techMatchesLabel(techSet map[string]bool, label string) bool {
	for tech := range techSet {
		if strings.Contains(tech, label) || strings.Contains(label, tech) {
			return true
		}
	}
	return false
}

// LoadTemplateVersion reads the .version file inside the template directory.
// Returns the version string (e.g. "v0.1.0") or an empty string if not found.
func LoadTemplateVersion(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, ".version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
