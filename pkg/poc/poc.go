package poc

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
	"gopkg.in/yaml.v3"
)

type PoC struct {
	Name       string            `yaml:"name"`
	Transport  string            `yaml:"transport"`
	Set        map[string]string `yaml:"set"`
	Rules      map[string]*Rule  `yaml:"rules"`
	Expression string            `yaml:"expression"`
	Detail     Detail            `yaml:"detail"`
	path       string
}

type Rule struct {
	Request    Request `yaml:"request"`
	Expression string  `yaml:"expression"`
}

type Request struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Tags        string   `yaml:"tags"`
	Endpoint    string   `yaml:"endpoint"`
}

type Response struct {
	Status      int
	Body        string
	Headers     map[string][]string
	ContentType string
	LatencyMs   int64
}

func LoadDir(dir string) ([]*PoC, error) {
	var out []*PoC
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(p), ".yaml") && !strings.HasSuffix(strings.ToLower(p), ".yml") {
			return nil
		}
		poc, err := LoadFile(p)
		if err != nil {
			return nil
		}
		if poc != nil {
			out = append(out, poc)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func LoadFile(path string) (*PoC, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p PoC
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.path = path
	if p.Name == "" {
		return nil, fmt.Errorf("%s: missing 'name'", path)
	}
	if p.Transport == "" {
		p.Transport = "http"
	}
	return &p, nil
}

func (p *PoC) Severity() string {
	if p.Detail.Severity != "" {
		return p.Detail.Severity
	}
	return "info"
}

func (p *PoC) Lint() []string {
	var errs []string
	if p.Name == "" {
		errs = append(errs, "missing 'name'")
	}
	if len(p.Rules) == 0 {
		errs = append(errs, "no 'rules' defined")
	}
	if p.Expression == "" {
		errs = append(errs, "missing 'expression'")
	}
	for name, r := range p.Rules {
		if r == nil {
			errs = append(errs, fmt.Sprintf("rule %q: empty request", name))
			continue
		}
		if r.Request.Method == "" && r.Request.Path == "" {
			errs = append(errs, fmt.Sprintf("rule %q: empty request", name))
		}
		if r.Expression == "" {
			errs = append(errs, fmt.Sprintf("rule %q: missing 'expression'", name))
		}
	}
	return errs
}

func (p *PoC) Run(client *http.Client, baseURL string) (bool, *Response, error) {
	set, err := p.evalSet()
	if err != nil {
		return false, nil, err
	}
	rulesRes := map[string]*Response{}
	ruleMatched := map[string]bool{}
	names := make([]string, 0, len(p.Rules))
	for name := range p.Rules {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return false, nil, nil
	}
	var firstMatched string
	for _, name := range names {
		r := p.Rules[name]
		if r == nil {
			return false, nil, fmt.Errorf("rule %q: empty (nil) rule", name)
		}
		match, resp, rerr := p.runRule(client, baseURL, r, set)
		if rerr != nil {
			return false, nil, rerr
		}
		rulesRes[name] = resp
		ruleMatched[name] = match
		if match && firstMatched == "" {
			firstMatched = name
		}
	}
	if p.Expression == "" {
		return false, nil, nil
	}
	matched, err := evalBool(render(p.Expression, set), evalCtx{set: set, resp: nil, rules: ruleMatched})
	if err != nil {
		return false, nil, err
	}
	if firstMatched == "" {
		firstMatched = names[0]
	}
	return matched, rulesRes[firstMatched], nil
}

func (p *PoC) FirstRule() string {
	names := make([]string, 0, len(p.Rules))
	for name := range p.Rules {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func (p *PoC) evalSet() (map[string]string, error) {
	set := map[string]string{}
	order := make([]string, 0, len(p.Set))
	for k := range p.Set {
		order = append(order, k)
	}
	sort.Strings(order)
	for _, k := range order {
		v, err := evalValue(render(p.Set[k], set), evalCtx{set: set, resp: nil, rules: map[string]bool{}})
		if err != nil {
			return nil, fmt.Errorf("set %q: %w", k, err)
		}
		set[k] = toStr(v)
	}
	return set, nil
}

func (p *PoC) runRule(client *http.Client, baseURL string, r *Rule, set map[string]string) (bool, *Response, error) {
	method := r.Request.Method
	if method == "" {
		method = "GET"
	}
	path := render(r.Request.Path, set)
	body := render(r.Request.Body, set)
	full := resolveURL(baseURL, path)
	req, err := http.NewRequest(strings.ToUpper(method), full, strings.NewReader(body))
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("User-Agent", "sxel-poc")
	for k, v := range r.Request.Headers {
		hv := render(v, set)
		if strings.EqualFold(k, "Host") {
			req.Host = hv
		} else {
			req.Header.Set(k, hv)
		}
	}
	if body != "" && r.Request.Headers == nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	start := time.Now()
	var resp *http.Response
	if r.Request.FollowRedirects {
		resp, err = client.Do(req)
	} else {
		transport := &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		}
		if base := core.BaseTransportFor(client); base != nil {
			if base.Proxy != nil {
				transport.Proxy = base.Proxy
			}
			if base.TLSClientConfig != nil {
				transport.TLSClientConfig = base.TLSClientConfig.Clone()
			}
			if base.DialContext != nil {
				transport.DialContext = base.DialContext
			}
		}
		resp, err = (&http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, v []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	}
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	latency := time.Since(start).Milliseconds()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	ct := resp.Header.Get("Content-Type")
	rr := &Response{
		Status:      resp.StatusCode,
		Body:        string(raw),
		Headers:     resp.Header,
		ContentType: ct,
		LatencyMs:   latency,
	}
	if r.Expression == "" {
		return true, rr, nil
	}
	matched, err := evalBool(render(r.Expression, set), evalCtx{set: set, resp: rr, rules: map[string]bool{}})
	return matched, rr, err
}

func resolveURL(base, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	b, err := url.Parse(base)
	if err != nil {
		return base + path
	}
	if path == "" {
		return base
	}
	if strings.HasPrefix(path, "/") {
		if i := strings.IndexByte(path, '?'); i >= 0 {
			b.Path = path[:i]
			b.RawQuery = path[i+1:]
		} else {
			b.Path = path
		}
	} else {
		basePath := b.Path
		idx := strings.LastIndex(basePath, "/")
		if idx >= 0 {
			basePath = basePath[:idx+1]
		}
		var cleanPath, rawQuery string
		if qi := strings.IndexByte(path, '?'); qi >= 0 {
			cleanPath = path[:qi]
			rawQuery = path[qi+1:]
		} else {
			cleanPath = path
		}
		b.Path = basePath + cleanPath
		if rawQuery != "" {
			b.RawQuery = rawQuery
		}
	}
	return b.String()
}

func render(s string, set map[string]string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	re := regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)
	return re.ReplaceAllStringFunc(s, func(m string) string {
		sub := re.FindStringSubmatch(m)
		if v, ok := set[sub[1]]; ok {
			return v
		}
		return m
	})
}

func evalValue(src string, c evalCtx) (interface{}, error) {
	node, err := parseExpr(src)
	if err != nil {
		return nil, err
	}
	return node.eval(c)
}

func (p *PoC) ToResult(baseURL string, resp *Response) core.ScanResult {
	sev := p.Severity()
	switch strings.ToLower(sev) {
	case "critical":
		sev = "CRITICAL"
	case "high":
		sev = "HIGH"
	case "medium":
		sev = "MEDIUM"
	case "low":
		sev = "LOW"
	default:
		sev = "MEDIUM"
	}
	evid := respBodySnippet(resp)
	if evid == "" {
		evid = p.Name
	}
	return core.ScanResult{
		Type:      "poc",
		URL:       baseURL,
		Method:    "GET",
		Severity:  sev,
		Evidence:  evid,
		Payload:   p.Name,
		Extra:     map[string]string{"poc": p.Name, "file": p.path, "tags": p.Detail.Tags, "severity_raw": p.Detail.Severity},
		Timestamp: time.Now(),
	}
}

func respBodySnippet(resp *Response) string {
	if resp == nil {
		return ""
	}
	body := strings.TrimSpace(resp.Body)
	if len(body) > 300 {
		return body[:300]
	}
	return body
}

func toStr(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case bool:
		return fmt.Sprintf("%v", t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

var hashFns = map[string]func(string) string{
	"md5":          func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) },
	"sha1":         func(s string) string { h := sha1.Sum([]byte(s)); return hex.EncodeToString(h[:]) },
	"sha256":       func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) },
	"base64":       func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
	"base64encode": func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
	"urlencode":    func(s string) string { return url.QueryEscape(s) },
	"tolower":      strings.ToLower,
	"toupper":      strings.ToUpper,
}

var (
	rnd   = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	rndMu sync.Mutex
)

func rndIntn(n int) int {
	rndMu.Lock()
	defer rndMu.Unlock()
	return rnd.Intn(n)
}

func rndIntRange(lo, hi int) int {
	if hi <= lo {
		hi = lo + 1
	}
	rndMu.Lock()
	defer rndMu.Unlock()
	return rnd.Intn(hi-lo) + lo
}

func rndBytes(chars string, n int) string {
	if n <= 0 {
		n = 8
	}
	rndMu.Lock()
	defer rndMu.Unlock()
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte(chars[rnd.Intn(len(chars))])
	}
	return sb.String()
}
