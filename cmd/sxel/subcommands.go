package main

import (
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/engine"
	"github.com/SentinelXofficial/sxel/pkg/poc"
	"gopkg.in/yaml.v3"
)

func runPocLint(args []string) {
	fs := flag.NewFlagSet("poclint", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: sxel poclint <file.yaml|dir>")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}
	path := fs.Arg(0)
	st, err := os.Stat(path)
	if err != nil {
		output.Error("cannot access %s: %v", path, err)
		os.Exit(1)
	}
	var list []*poc.PoC
	if st.IsDir() {
		list, err = poc.LoadDir(path)
		if err != nil {
			output.Error("load dir: %v", err)
			os.Exit(1)
		}
	} else {
		p, lerr := poc.LoadFile(path)
		if lerr != nil {
			output.Error("cannot parse %s: %v", path, lerr)
			os.Exit(1)
		}
		list = []*poc.PoC{p}
	}
	bad := 0
	for _, p := range list {
		errs := p.Lint()
		if len(errs) == 0 {
			output.Success("OK %s (%s)", p.Name, p.Severity())
		} else {
			bad++
			for _, e := range errs {
				output.Error("%s: %s", p.Name, e)
			}
		}
	}
	if bad > 0 {
		output.Error("%d PoC(s) failed lint", bad)
		os.Exit(1)
	}
	output.Success("%d PoC(s) linted, all OK", len(list))
}

func runServiceScan(args []string) {
	fs := flag.NewFlagSet("servicescan", flag.ExitOnError)
	host := fs.String("host", "", "Target host or IP")
	ports := fs.String("ports", "21,22,23,25,53,80,110,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9000,9200,27017", "Comma-separated ports")
	timeout := fs.Int("timeout", 3, "Connect timeout in seconds")
	fs.Usage = func() {
		fmt.Println("Usage: sxel servicescan --host <host> [--ports 22,80,443] [--timeout 3]")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if *host == "" {
		fs.Usage()
		os.Exit(1)
	}
	var plist []int
	for _, p := range strings.Split(*ports, ",") {
		p = strings.TrimSpace(p)
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			plist = append(plist, n)
		}
	}
	timeoutD := time.Duration(*timeout) * time.Second
	var open []int
	for _, port := range plist {
		addr := net.JoinHostPort(*host, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, timeoutD)
		if err != nil {
			continue
		}
		open = append(open, port)
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		banner := strings.TrimSpace(string(buf[:n]))
		conn.Close()
		output.Success("open %s:%d  service=%s  banner=%q", *host, port, serviceName(port), truncate(banner, 80))
	}
	if len(open) == 0 {
		output.Warn("no open ports found on %s (checked %d)", *host, len(plist))
		return
	}
	output.Info("done: %d open port(s) on %s", len(open), *host)
}

func serviceName(port int) string {
	m := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
		143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp-submission", 993: "imaps",
		995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgres",
		5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9000: "php-fpm",
		9200: "elasticsearch", 27017: "mongodb",
	}
	if s, ok := m[port]; ok {
		return s
	}
	return "unknown"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func runReverse(args []string) {
	fs := flag.NewFlagSet("reverse", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: sxel reverse [--dns-addr 0.0.0.0:53]")
		fs.PrintDefaults()
	}
	dnsAddr := fs.String("dns-addr", "0.0.0.0:53", "DNS listener address (needs root for :53)")
	fs.Parse(args)
	oob, err := engine.NewOOBServer()
	if err != nil {
		output.Error("cannot start OOB HTTP server: %v", err)
		os.Exit(1)
	}
	defer oob.Close()
	output.Success("OOB HTTP callback server listening on %s (any path = callback)", oob.Address)
	dns, derr := engine.NewDNSOOB(*dnsAddr)
	if derr != nil {
		output.Warn("cannot start DNS OOB listener on %s: %v", *dnsAddr, derr)
	} else {
		defer dns.Close()
		output.Success("OOB DNS listener on %s — use any subdomain as callback", *dnsAddr)
	}
	output.Info("callback URL: http://%s/sxel_probe", oob.Address)
	output.Info("press Ctrl+C to stop")
	seen := map[string]bool{}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for range tick.C {
		for _, cb := range oob.CallbacksSnapshot() {
			key := cb.ID
			if !seen[key] {
				seen[key] = true
				output.Success("[http] callback vuln=%s target=%s method=%s payload=%s", cb.VulnType, cb.TargetURL, cb.Method, cb.Payload)
			}
		}
		if dns != nil {
			for _, q := range dns.Queries() {
				key := q.QName + q.From
				if !seen[key] {
					seen[key] = true
					output.Success("[dns] %s from %s", q.QName, q.From)
				}
			}
		}
	}
}

type burpItem struct {
	URL      string `xml:"url"`
	Method   string `xml:"method"`
	Request  string `xml:"request"`
	Response string `xml:"response"`
}

type burpItems struct {
	Items []burpItem `xml:"item"`
}

func runBurpGamma(args []string) {
	fs := flag.NewFlagSet("burp-gamma", flag.ExitOnError)
	in := fs.String("in", "", "Burp Suite XML export file")
	out := fs.String("out", "./pocs/burp-", "Output YAML PoC prefix (per-request file: <out><n>.yaml)")
	fs.Usage = func() {
		fmt.Println("Usage: sxel burp-gamma --in burp.xml [--out ./pocs/burp-]")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if *in == "" {
		fs.Usage()
		os.Exit(1)
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		output.Error("cannot read %s: %v", *in, err)
		os.Exit(1)
	}
	var items burpItems
	if err := xml.Unmarshal(data, &items); err != nil {
		output.Error("invalid burp XML: %v", err)
		os.Exit(1)
	}
	if len(items.Items) == 0 {
		output.Warn("no items found in %s", *in)
		return
	}
	written := 0
	for i, it := range items.Items {
		raw := parseBurpRequest(it.Request)
		hdrs, body := splitBurpRequest(raw)
		u, uerr := url.Parse(it.URL)
		if uerr != nil {
			continue
		}
		p := buildGammaFromParts(it.Method, u.Path+querySuffix(u), body, hdrs)
		name := fmt.Sprintf("poc-burp-%d", i+1)
		p.Name = name
		p.Detail = poc.Detail{Author: "burp-gamma", Severity: "info", Description: "converted from burp history " + it.URL}
		path := fmt.Sprintf("%s%d.yaml", *out, i+1)
		rawYaml, _ := yaml.Marshal(p)
		if err := os.WriteFile(path, rawYaml, 0o644); err != nil {
			output.Error("cannot write %s: %v", path, err)
			continue
		}
		written++
		output.Success("%s -> %s (%s)", it.Method, it.URL, path)
	}
	output.Info("done: %d gamma PoC(s) written", written)
}

func querySuffix(u *url.URL) string {
	if u.RawQuery != "" {
		return "?" + u.RawQuery
	}
	return ""
}

func buildGammaFromParts(method, path string, body string, headers map[string]string) *poc.PoC {
	rules := map[string]*poc.Rule{
		"r0": {
			Request:    poc.Request{Method: method, Path: path, Body: body, Headers: headers},
			Expression: "response.status == 200",
		},
	}
	return &poc.PoC{
		Transport:  "http",
		Rules:      rules,
		Expression: "r0()",
	}
}

// splitBurpRequest separates a raw HTTP request into its headers (minus Host
// and Content-Length, which are recomputed on replay) and body. Handles both
// CRLF and LF line endings.
func splitBurpRequest(raw string) (map[string]string, string) {
	headers := map[string]string{}
	var head, body string
	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
		head, body = raw[:idx], raw[idx+4:]
	} else if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		head, body = raw[:idx], raw[idx+2:]
	} else {
		return headers, strings.TrimSpace(raw)
	}
	lines := strings.Split(head, "\r\n")
	if len(lines) == 1 {
		lines = strings.Split(head, "\n")
	}
	for _, ln := range lines[1:] {
		c := strings.Index(ln, ":")
		if c <= 0 {
			continue
		}
		k := strings.TrimSpace(ln[:c])
		v := strings.TrimSpace(ln[c+1:])
		if k == "" || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		headers[k] = v
	}
	return headers, body
}

func parseBurpRequest(req string) string {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req))
	if err != nil {
		return strings.TrimSpace(req)
	}
	return string(decoded)
}

func runTransform(args []string) {
	fs := flag.NewFlagSet("transform", flag.ExitOnError)
	in := fs.String("in", "", "Nuclei template file (.yaml)")
	out := fs.String("out", "", "Output gamma PoC path (default: <in>.gamma.yaml)")
	fs.Usage = func() {
		fmt.Println("Usage: sxel transform --in nuclei-template.yaml [--out poc.yaml]")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if *in == "" {
		fs.Usage()
		os.Exit(1)
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		output.Error("cannot read %s: %v", *in, err)
		os.Exit(1)
	}
	var n nucleiTemplate
	if err := yaml.Unmarshal(data, &n); err != nil {
		output.Error("invalid nuclei template: %v", err)
		os.Exit(1)
	}
	if len(n.Requests) == 0 {
		output.Error("no http requests found (only http templates supported)")
		os.Exit(1)
	}
	req := n.Requests[0]
	method := req.Method
	if method == "" {
		method = "GET"
	}
	path := "/"
	if len(req.Path) > 0 {
		path = req.Path[0]
	}
	if req.Raw != nil && len(req.Raw) > 0 {
		path = rawPath(req.Raw[0])
	}
	path = strings.ReplaceAll(path, "{{BaseURL}}", "")
	path = strings.ReplaceAll(path, "{{RootURL}}", "")
	p := buildGammaFromParts(method, path, req.Body, nil)
	if n.Info.Name != "" {
		p.Name = strings.ReplaceAll(n.Info.Name, " ", "-")
	}
	p.Name = strings.ToLower(p.Name)
	p.Detail.Severity = n.Info.Severity
	p.Detail.Tags = n.Info.Tags
	expr, ok := nucleiMatchers(req, n.Info.Severity)
	if !ok {
		output.Error("no supported matchers found (status/words/regex)")
		os.Exit(1)
	}
	p.Rules["r0"].Expression = expr
	outPath := *out
	if outPath == "" {
		outPath = *in + ".gamma.yaml"
	}
	raw, _ := yaml.Marshal(p)
	if err := os.WriteFile(outPath, raw, 0o644); err != nil {
		output.Error("cannot write %s: %v", outPath, err)
		os.Exit(1)
	}
	output.Success("%s -> %s", *in, outPath)
}

func rawPath(raw string) string {
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		if i == 0 {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return "/"
}

type nucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
		Tags     string `yaml:"tags"`
	} `yaml:"info"`
	Requests []struct {
		Method            string   `yaml:"method"`
		Path              []string `yaml:"path"`
		Raw               []string `yaml:"raw"`
		Body              string   `yaml:"body"`
		MatchersCondition string   `yaml:"matchers-condition"`
		Matchers          []struct {
			Type   string   `yaml:"type"`
			Status []int    `yaml:"status"`
			Words  []string `yaml:"words"`
			Regex  []string `yaml:"regex"`
		} `yaml:"matchers"`
	} `yaml:"requests"`
}

func nucleiMatchers(req struct {
	Method            string   `yaml:"method"`
	Path              []string `yaml:"path"`
	Raw               []string `yaml:"raw"`
	Body              string   `yaml:"body"`
	MatchersCondition string   `yaml:"matchers-condition"`
	Matchers          []struct {
		Type   string   `yaml:"type"`
		Status []int    `yaml:"status"`
		Words  []string `yaml:"words"`
		Regex  []string `yaml:"regex"`
	} `yaml:"matchers"`
}, severity string) (string, bool) {
	if len(req.Matchers) == 0 {
		return "response.status == 200", true
	}
	var parts []string
	for _, m := range req.Matchers {
		switch m.Type {
		case "status":
			for _, s := range m.Status {
				parts = append(parts, fmt.Sprintf("response.status == %d", s))
			}
		case "word":
			for _, w := range m.Words {
				parts = append(parts, fmt.Sprintf("response.body.bcontains(%q)", w))
			}
		case "regex":
			for _, r := range m.Regex {
				parts = append(parts, fmt.Sprintf("response.body.bmatches(%q)", r))
			}
		}
	}
	if len(parts) == 0 {
		return "response.status == 200", true
	}
	if req.MatchersCondition == "and" {
		return strings.Join(parts, " && "), true
	}
	return strings.Join(parts, " || "), true
}
