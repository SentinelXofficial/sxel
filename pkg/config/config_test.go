package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sxel.yml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFull(t *testing.T) {
	p := writeTemp(t, `
targets:
  - http://a.example.com
  - https://b.example.com
wordlist: /tmp/wl.txt
cookie: "session=abc"
rate-limit: 12
scope: "*.example.com"
out-of-scope: "cdn.example.com"
threads: 8
timeout: 30
delay: 250
max-pages: 500
exclude: /logout
proxy: http://127.0.0.1:8080
user-agent: "CustomUA/1.0"
headers:
  - "X-Api-Key: k1"
  - "Authorization: Bearer t2"
report:
  html: out.html
  json: out.json
  csv: out.csv
  md: out.md
  evidence-dir: ./ev
modules:
  crawl: true
  blind: false
  dirscan: true
flags:
  list-concurrency: "5"
`)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Targets) != 2 || f.Targets[0] != "http://a.example.com" {
		t.Errorf("targets = %v", f.Targets)
	}
	if f.Wordlist != "/tmp/wl.txt" || f.Cookie != "session=abc" {
		t.Errorf("wordlist/cookie = %q %q", f.Wordlist, f.Cookie)
	}
	if f.RateLimit == nil || *f.RateLimit != 12 {
		t.Errorf("rate-limit = %v", f.RateLimit)
	}
	if f.Threads == nil || *f.Threads != 8 || f.Timeout == nil || *f.Timeout != 30 {
		t.Errorf("threads/timeout = %v %v", f.Threads, f.Timeout)
	}
	if f.Delay == nil || *f.Delay != 250 || f.MaxPages == nil || *f.MaxPages != 500 {
		t.Errorf("delay/max-pages = %v %v", f.Delay, f.MaxPages)
	}
	if f.Proxy != "http://127.0.0.1:8080" || f.UserAgent != "CustomUA/1.0" {
		t.Errorf("proxy/ua = %q %q", f.Proxy, f.UserAgent)
	}
	if len(f.Headers) != 2 || f.Report.HTML != "out.html" || f.Report.EvidenceDir != "./ev" {
		t.Errorf("headers/report = %v %+v", f.Headers, f.Report)
	}
	if !f.Modules["crawl"] || f.Modules["blind"] || !f.Modules["dirscan"] {
		t.Errorf("modules = %v", f.Modules)
	}
}

func TestFlagValues(t *testing.T) {
	p := writeTemp(t, `
rate-limit: 3
modules:
  crawl: true
  dirscan: false
flags:
  user-agent: "FromFlags/1.0"
report:
  json: r.json
`)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	vals := f.FlagValues()
	cases := map[string]string{
		"rate-limit":  "3",
		"crawl":       "true",
		"dirscan":     "false",
		"user-agent":  "FromFlags/1.0",
		"json-output": "r.json",
	}
	for k, want := range cases {
		if vals[k] != want {
			t.Errorf("FlagValues[%s] = %q, want %q", k, vals[k], want)
		}
	}
	if _, ok := vals["u"]; ok {
		t.Error("targets should not map to a flag directly")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yml")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	p := writeTemp(t, "modules: [unclosed\n")
	if _, err := Load(p); err == nil {
		t.Error("expected error for invalid yaml")
	}
}

func TestFindIn(t *testing.T) {
	dir := t.TempDir()
	if got := FindIn(dir); got != "" {
		t.Errorf("empty dir should not match, got %q", got)
	}
	os.WriteFile(filepath.Join(dir, "sxel.yaml"), []byte("threads: 4"), 0o644)
	if got := FindIn(dir); got != filepath.Join(dir, "sxel.yaml") {
		t.Errorf("FindIn = %q", got)
	}
}

func TestProfiles(t *testing.T) {
	for _, name := range ValidProfiles() {
		m, ok := ProfileFlags(name)
		if !ok {
			t.Errorf("profile %q missing", name)
		}
		if len(m) == 0 {
			t.Errorf("profile %q empty", name)
		}
	}
	if _, ok := ProfileFlags("nope"); ok {
		t.Error("unknown profile should not be valid")
	}
	if ProfileSummary("quick") == "" || ProfileSummary("deep") == "" || ProfileSummary("snipe") == "" {
		t.Error("profile summaries missing")
	}
}

func TestProfileFlagsAreRealFlags(t *testing.T) {
	known := map[string]bool{
		"crawl": true, "header-scan": true, "cookie-scan": true,
		"security-headers": true, "cookie-audit": true, "csrf": true,
		"open-redirect": true, "http-methods": true, "lfi": true,
		"cmdi": true, "ssrf": true, "nosql": true, "idor": true,
		"cors": true, "ssti": true, "crlf": true, "hpp": true,
		"json-injection": true, "ws": true, "js-endpoints": true,
		"robots": true, "all": true, "blind": true, "dom-audit": true,
		"js-crawl": true, "dirscan": true, "subdomain-enum": true,
		"subdomain-takeover": true, "waf-detect": true,
		"rate-limit-test": true, "breach": true, "strobe": true,
		"grpc": true, "smuggling": true, "cache-poison": true,
		"waf-bypass": true, "snipe": true, "rate-limit": true,
		"sqli": true, "xss": true, "path-traversal": true,
		"file-upload": true, "webshell": true, "poc": true,
	}
	for _, name := range ValidProfiles() {
		m, _ := ProfileFlags(name)
		for k := range m {
			if !known[k] {
				t.Errorf("profile %q references unknown flag %q", name, k)
			}
		}
	}
}
