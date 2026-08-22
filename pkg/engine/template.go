package engine

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"gopkg.in/yaml.v3"
)

type Template struct {
	ID    string         `yaml:"id"`
	Brief TemplateBrief  `yaml:"brief"`
	Moves []TemplateMove `yaml:"moves"`
}

type TemplateBrief struct {
	Title string   `yaml:"title"`
	By    string   `yaml:"by"`
	Level string   `yaml:"level"`
	About string   `yaml:"about"`
	Label []string `yaml:"label,omitempty"`
	Score string   `yaml:"score,omitempty"`
}

type TemplateMove struct {
	Verb    string            `yaml:"verb"`
	To      []string          `yaml:"to"`
	Head    map[string]string `yaml:"head,omitempty"`
	Body    string            `yaml:"body,omitempty"`
	Signs   []TemplateSign    `yaml:"signs"`
	Capture []string          `yaml:"capture,omitempty"`
}

type TemplateSign struct {
	On     string   `yaml:"on"`
	Has    []string `yaml:"has,omitempty"`
	In     string   `yaml:"in,omitempty"`
	Need   string   `yaml:"need,omitempty"`
	Flip   bool     `yaml:"flip,omitempty"`
	Status []int    `yaml:"status,omitempty"`
}

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
			return nil
		}
		var tmpl Template
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil
		}
		if tmpl.ID == "" || len(tmpl.Moves) == 0 {
			return nil
		}
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

func RunTemplates(client *http.Client, cfg *core.Config, targetURL string, templates []Template) []core.ScanResult {
	var results []core.ScanResult
	base, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	baseURL := fmt.Sprintf("%s://%s", base.Scheme, base.Host)
	hostname := base.Host

	spaBaseline, isSPA := detectSPABaseline(client, cfg, baseURL)

	for _, tmpl := range templates {
		if !matchMinSeverity(tmpl.Brief.Level, cfg.TemplateSeverity) {
			continue
		}
		vars := map[string]string{}
		for _, move := range tmpl.Moves {
			for _, rawPath := range move.To {
				oobURL := cfg.OOBAddress
				if oobURL == "" {
					oobURL = "127.0.0.1:0"
				}
				oobDomain := cfg.OOBDomain

				reqURL := expandTemplateVars(rawPath, baseURL, hostname, oobURL, oobDomain, vars)
				reqURL = resolveTemplateURL(baseURL, reqURL)

				reqBody := expandTemplateVars(move.Body, baseURL, hostname, oobURL, oobDomain, vars)

				req, err := http.NewRequest(move.Verb, reqURL, strings.NewReader(reqBody))
				if err != nil {
					continue
				}
				core.ApplyHeaders(req, cfg)
				for k, v := range move.Head {
					req.Header.Set(k, expandTemplateVars(v, baseURL, hostname, oobURL, oobDomain, vars))
				}

				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				bodyStr := core.ReadBody(resp.Body)
				resp.Body.Close()

				applyCaptures(move.Capture, bodyStr, vars)

				if matchSigns(move.Signs, bodyStr, resp) {
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
							"template_id": tmpl.ID,
							"score":       tmpl.Brief.Score,
						},
					})
					output.VulnInline("TPL", "%s → %s [%s]", tmpl.ID, tmpl.Brief.Title, sev)
					break
				}
			}
		}
	}
	return results
}

func RunSingleTemplate(client *http.Client, cfg *core.Config, tmpl Template, targetURL string) []core.ScanResult {
	return RunTemplates(client, cfg, targetURL, []Template{tmpl})
}

var (
	tmplVarToken = regexp.MustCompile(`\{\{([^{}]+)\}\}`)
	mrandOnce    sync.Once
	mrandMu      sync.Mutex
	mrandRng     *mrand.Rand
)

func mrandSource() *mrand.Rand {
	mrandOnce.Do(func() {
		mrandRng = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	})
	return mrandRng
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		r := mrandSource()
		mrandMu.Lock()
		for i := range b {
			b[i] = byte(r.Intn(256))
		}
		mrandMu.Unlock()
	}
	return b
}

func randomInt(min, max int) int {
	span := int64(max) - int64(min) + 1
	if span <= 0 {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		mrandMu.Lock()
		n = big.NewInt(mrandSource().Int63n(span))
		mrandMu.Unlock()
	}
	return int(n.Int64()) + min
}

func randomHex(n int) string {
	h := hex.EncodeToString(randBytes((n + 1) / 2))
	if len(h) > n {
		h = h[:n]
	}
	return h
}

func ExpandTemplateVars(s, baseURL, hostname, oobURL, oobDomain string) string {
	return expandTemplateVars(s, baseURL, hostname, oobURL, oobDomain, nil)
}

func resolveTemplateURL(baseURL, raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" {
		return raw
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return raw
	}
	return base.ResolveReference(u).String()
}

func expandTemplateVars(s, baseURL, hostname, oobURL, oobDomain string, vars map[string]string) string {
	s = strings.ReplaceAll(s, "{{BaseURL}}", baseURL)
	s = strings.ReplaceAll(s, "{{Hostname}}", hostname)
	s = strings.ReplaceAll(s, "{{interactsh-url}}", oobURL)
	s = strings.ReplaceAll(s, "{{OOB_URL}}", oobURL)

	for i := 0; i < 10; i++ {
		expanded := tmplVarToken.ReplaceAllStringFunc(s, func(tok string) string {
			return expandTemplateToken(tok, baseURL, hostname, oobURL, oobDomain, vars)
		})
		if expanded == s {
			return expanded
		}
		s = expanded
	}
	return s
}

func expandTemplateToken(tok, baseURL, hostname, oobURL, oobDomain string, vars map[string]string) string {
	m := tmplVarToken.FindStringSubmatch(tok)
	if m == nil {
		return tok
	}
	name, args, _ := strings.Cut(m[1], ":")
	switch name {
	case "path-int":
		return strconv.Itoa(randomInt(100000, 999999))
	case "jsonp":
		return "sxelCallback" + randomHex(4)
	case "dnslog":
		return TemplateDnslogName(oobDomain)
	case "base64":
		enc := base64.StdEncoding.EncodeToString([]byte(expandTemplateVars(args, baseURL, hostname, oobURL, oobDomain, vars)))
		return enc
	case "str-replace":
		parts := strings.Split(expandTemplateVars(args, baseURL, hostname, oobURL, oobDomain, vars), "|")
		if len(parts) < 3 {
			return tok
		}
		return strings.ReplaceAll(strings.Join(parts[2:], "|"), parts[0], parts[1])
	case "compare":
		parts := strings.Split(expandTemplateVars(args, baseURL, hostname, oobURL, oobDomain, vars), "|")
		if len(parts) == 1 {
			if parts[0] != "" {
				return "1"
			}
			return "0"
		}
		if len(parts) > 1 && parts[0] == parts[1] {
			return "1"
		}
		return "0"
	case "x-www-form-urlencoded":
		return url.QueryEscape(expandTemplateVars(args, baseURL, hostname, oobURL, oobDomain, vars))
	case "json":
		b, err := json.Marshal(expandTemplateVars(args, baseURL, hostname, oobURL, oobDomain, vars))
		if err != nil {
			return tok
		}
		out := string(b)
		if len(out) >= 2 {
			out = out[1 : len(out)-1]
		}
		return out
	case "vars":
		if vars != nil {
			if v, ok := vars[args]; ok {
				return v
			}
		}
		return tok
	default:
		return tok
	}
}

func TemplateDnslogName(oobDomain string) string {
	if oobDomain != "" {
		return randomHex(8) + "." + oobDomain
	}
	return randomHex(8) + ".dnslog"
}

func applyCaptures(captures []string, body string, vars map[string]string) {
	for _, c := range captures {
		name, pattern, ok := strings.Cut(c, "=")
		if !ok || name == "" || pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		m := re.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		if len(m) > 1 {
			vars[name] = m[1]
		} else {
			vars[name] = m[0]
		}
	}
}

func matchSigns(signs []TemplateSign, body string, resp *http.Response) bool {
	if len(signs) == 0 {
		return false
	}
	var wordSigns, statusSigns []TemplateSign
	for _, s := range signs {
		if s.On == "status" || (s.On != "word" && len(s.Status) > 0) {
			statusSigns = append(statusSigns, s)
		} else {
			wordSigns = append(wordSigns, s)
		}
	}

	statusOK := evalStatusGroup(statusSigns, resp)

	if len(wordSigns) > 0 {
		matched := 0
		for _, s := range wordSigns {
			if matchWords(s, body, resp) {
				matched++
			}
		}
		if allSignsNeedAll(wordSigns) {
			return statusOK && matched == len(wordSigns)
		}
		return statusOK && matched > 0
	}

	return statusOK
}

func allSignsNeedAll(signs []TemplateSign) bool {
	for _, s := range signs {
		if s.Need != "all" {
			return false
		}
	}
	return len(signs) > 0
}

func evalStatusGroup(statusSigns []TemplateSign, resp *http.Response) bool {
	if len(statusSigns) == 0 {
		return true
	}
	matched := 0
	for _, s := range statusSigns {
		if matchStatus(s, resp) {
			matched++
		}
	}
	if allSignsNeedAll(statusSigns) {
		return matched == len(statusSigns)
	}
	return matched > 0
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

var severityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
}

func matchMinSeverity(level, min string) bool {
	if min == "" || min == "info" {
		return true
	}
	minR := severityRank[strings.ToLower(min)]
	lvlR := severityRank[strings.ToLower(level)]
	if minR == 0 {
		minR = 4
	}
	if lvlR == 0 {
		lvlR = 3
	}
	return lvlR >= minR
}

type spaBaseline struct {
	body   string
	length int
	status int
}

func detectSPABaseline(client *http.Client, cfg *core.Config, baseURL string) (spaBaseline, bool) {
	bogusURL := baseURL + "/sxel_nonexistent_" + fmt.Sprintf("%d", time.Now().UnixNano()/1000)
	body, status, err := core.DoGET(client, cfg, bogusURL)
	if err != nil || status == 404 || status == 0 {
		return spaBaseline{}, false
	}
	return spaBaseline{body: body, length: len(body), status: status}, status >= 200 && status < 400
}

func isSPAFalsePositive(body string, bl spaBaseline) bool {
	if bl.length == 0 {
		return false
	}
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

func FilterTemplatesByTech(templates []Template, detectedTech []string) []Template {
	techSet := make(map[string]bool, len(detectedTech))
	for _, t := range detectedTech {
		techSet[strings.ToLower(t)] = true
	}

	var filtered []Template
	for _, tmpl := range templates {
		var vendorLabels []string
		allGeneric := true
		for _, label := range tmpl.Brief.Label {
			if !genericLabels[strings.ToLower(label)] {
				allGeneric = false
				vendorLabels = append(vendorLabels, strings.ToLower(label))
			}
		}

		if allGeneric {
			filtered = append(filtered, tmpl)
			continue
		}

		if len(techSet) == 0 {
			continue
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

func techMatchesLabel(techSet map[string]bool, label string) bool {
	for tech := range techSet {
		if strings.Contains(tech, label) || strings.Contains(label, tech) {
			return true
		}
	}
	return false
}

func LoadTemplateVersion(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, ".version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
