package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Report struct {
	HTML        string `yaml:"html"`
	JSON        string `yaml:"json"`
	CSV         string `yaml:"csv"`
	MD          string `yaml:"md"`
	EvidenceDir string `yaml:"evidence-dir"`
}

type Engine struct {
	MaxQueryVariants  *int     `yaml:"max-query-variants"`
	HandshakeTimeout  *int     `yaml:"handshake-timeout"`
	SQLiMarginFactor  *float64 `yaml:"sqli-margin-factor"`
	SQLiConfirmFactor *float64 `yaml:"sqli-confirm-factor"`
}

type File struct {
	Targets    []string          `yaml:"targets"`
	Wordlist   string            `yaml:"wordlist"`
	Cookie     string            `yaml:"cookie"`
	RateLimit  *int              `yaml:"rate-limit"`
	Scope      string            `yaml:"scope"`
	OutOfScope string            `yaml:"out-of-scope"`
	Threads    *int              `yaml:"threads"`
	Timeout    *int              `yaml:"timeout"`
	Delay      *int              `yaml:"delay"`
	MaxPages   *int              `yaml:"max-pages"`
	Exclude    string            `yaml:"exclude"`
	Proxy      string            `yaml:"proxy"`
	UserAgent  string            `yaml:"user-agent"`
	Headers    []string          `yaml:"headers"`
	ClientCert string            `yaml:"client-cert"`
	ClientKey  string            `yaml:"client-key"`
	Report     Report            `yaml:"report"`
	Modules    map[string]bool   `yaml:"modules"`
	Flags      map[string]string `yaml:"flags"`
	Engine     Engine            `yaml:"engine"`
}

const (
	MasterFile   = "sx.sxel.yaml"
	ModulesFile  = "sx.modules.yaml"
	PluginsFile  = "sx.plugins.yaml"
	DefaultsFile = "sx.config.yaml"
)

func SetFiles() []string {
	return []string{MasterFile, ModulesFile, PluginsFile, DefaultsFile}
}

func Template(name string) (string, bool) {
	templates := map[string]string{
		MasterFile: `# sxel master config — mirrors xray.yaml. Edit, then run sxel (auto-detected in cwd or --config PATH).
# Companion files auto-loaded from the same dir: sx.modules.yaml, sx.plugins.yaml, sx.config.yaml
targets: []
# wordlist: ""
# cookie: ""
# scope: ""
# out-of-scope: ""
# proxy: ""
# user-agent: ""
# headers: []
# exclude: ""
report:
  # html: "report.html"
  # json: "report.json"
  # csv: "report.csv"
  # md: "report.md"
  # evidence-dir: "evidence/"
flags:
  # free-form flag overrides, e.g.:
  # crawl: "true"
  # blind: "true"
  # js-crawl: "true"
  # checkpoint: "state.json"
  # waf-bypass: "true"
  # sarif-output: "sarif.json"
`,
		ModulesFile: `# sxel modules + engine tuning — mirrors module.xray.yaml. Optional — defaults in code.
modules:
  # set true to enable a module (default when no modules/flags given: sqli, xss)
  # sqli: true
  # xss: true
  # webshell: true
  # cmdi: true
  # ssrf: true
  # xxe: true
  # nosql: true
  # ssti: true
  # lfi: true
  # open-redirect: true
  # path-traversal: true
  # crlf: true
  # hpp: true
  # cors: true
  # header-scan: true
  # cookie-scan: true
  # json-injection: true
  # host-header: true
  # security-headers: true
  # http-methods: true
  # sensitive-files: true
  # js-endpoints: true
  # dirscan: true
  # file-upload: true
  # jwt: true
  # idor: true
  # graphql: true
  # csrf: true
  # cookie-audit: true
  # proto-pollution: true
  # deserialize: true
  # cache-poison: true
  # smuggling: true
  # dom-audit: true
  # dom: true
  # ldap-xpath: true
  # h2c: true
  # jarm: true
  # mass-assign: true
  # axfr: true
  # subdomain-enum: true
  # subdomain-takeover: true
  # ws: true
  # waf-detect: true
  # rate-limit-test: true
  # templates: true

engine:
  # max query-variant pages crawled per path before dedup (default 10)
  # max-query-variants: 10
  # WebSocket / TE.TE smuggling deadline override in seconds (0 = use --timeout)
  # handshake-timeout: 0
  # fraction of SLEEP(n) required to flag a time-based delay (default 0.7)
  # sqli-margin-factor: 0.7
  # fraction of confirm SLEEP(n) required to confirm a finding (default 0.6)
  # sqli-confirm-factor: 0.6
`,
		PluginsFile: `# sxel pipeline / plugin tuning — mirrors plugin.xray.yaml. Optional — defaults in code.
# threads: 5
# timeout: 30
# delay: 100
# rate-limit: 10
# max-pages: 0
# exclude: ""
`,
		DefaultsFile: `# sxel scan defaults — mirrors config.yaml. Optional — defaults in code.
targets: []
# wordlist: ""
# proxy: ""
flags:
  # scan behavior defaults:
  # http-methods: "true"
  # security-headers: "true"
  # js-endpoints: "true"
  # sensitive-files: "true"
  # header-scan: "true"
  # cookie-scan: "true"
`,
	}
	t, ok := templates[name]
	return t, ok
}

func WriteSet(dir string) ([]string, error) {
	var written []string
	for _, name := range SetFiles() {
		tmpl, ok := Template(name)
		if !ok {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(tmpl), 0o644); err != nil {
			return written, err
		}
		written = append(written, name)
	}
	return written, nil
}

func FindCompanions(dir string) []string {
	var out []string
	for _, name := range []string{ModulesFile, PluginsFile, DefaultsFile} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

func Merge(into, from *File) {
	if len(from.Targets) > 0 {
		into.Targets = from.Targets
	}
	if from.Wordlist != "" {
		into.Wordlist = from.Wordlist
	}
	if from.Cookie != "" {
		into.Cookie = from.Cookie
	}
	if from.RateLimit != nil {
		into.RateLimit = from.RateLimit
	}
	if from.Scope != "" {
		into.Scope = from.Scope
	}
	if from.OutOfScope != "" {
		into.OutOfScope = from.OutOfScope
	}
	if from.Threads != nil {
		into.Threads = from.Threads
	}
	if from.Timeout != nil {
		into.Timeout = from.Timeout
	}
	if from.Delay != nil {
		into.Delay = from.Delay
	}
	if from.MaxPages != nil {
		into.MaxPages = from.MaxPages
	}
	if from.Exclude != "" {
		into.Exclude = from.Exclude
	}
	if from.Proxy != "" {
		into.Proxy = from.Proxy
	}
	if from.UserAgent != "" {
		into.UserAgent = from.UserAgent
	}
	if len(from.Headers) > 0 {
		into.Headers = from.Headers
	}
	if from.ClientCert != "" {
		into.ClientCert = from.ClientCert
	}
	if from.ClientKey != "" {
		into.ClientKey = from.ClientKey
	}
	if from.Report.HTML != "" {
		into.Report.HTML = from.Report.HTML
	}
	if from.Report.JSON != "" {
		into.Report.JSON = from.Report.JSON
	}
	if from.Report.CSV != "" {
		into.Report.CSV = from.Report.CSV
	}
	if from.Report.MD != "" {
		into.Report.MD = from.Report.MD
	}
	if from.Report.EvidenceDir != "" {
		into.Report.EvidenceDir = from.Report.EvidenceDir
	}
	if len(from.Modules) > 0 {
		if into.Modules == nil {
			into.Modules = map[string]bool{}
		}
		for k, v := range from.Modules {
			into.Modules[k] = v
		}
	}
	if len(from.Flags) > 0 {
		if into.Flags == nil {
			into.Flags = map[string]string{}
		}
		for k, v := range from.Flags {
			into.Flags[k] = v
		}
	}
	if from.Engine.MaxQueryVariants != nil {
		into.Engine.MaxQueryVariants = from.Engine.MaxQueryVariants
	}
	if from.Engine.HandshakeTimeout != nil {
		into.Engine.HandshakeTimeout = from.Engine.HandshakeTimeout
	}
	if from.Engine.SQLiMarginFactor != nil {
		into.Engine.SQLiMarginFactor = from.Engine.SQLiMarginFactor
	}
	if from.Engine.SQLiConfirmFactor != nil {
		into.Engine.SQLiConfirmFactor = from.Engine.SQLiConfirmFactor
	}
}

func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func WriteTemplate(path string) error {
	tmpl := `# sxel configuration — edit this file, then run sxel (auto-detected in cwd or --config PATH)
targets: []
# wordlist: ""
# cookie: ""
# scope: ""
# out-of-scope: ""
# proxy: ""
# user-agent: ""

modules:
  # set true to enable a module (default when no modules/flags given: sqli, xss)
  # sqli: true
  # xss: true
  # webshell: true
  # cmdi: true
  # ssrf: true
  # xxe: true
  # nosql: true
  # ssti: true
  # lfi: true
  # open-redirect: true
  # path-traversal: true
  # crlf: true
  # hpp: true
  # cors: true
  # header-scan: true
  # cookie-scan: true
  # json-injection: true
  # host-header: true
  # security-headers: true
  # http-methods: true
  # sensitive-files: true
  # js-endpoints: true
  # dirscan: true
  # file-upload: true
  # jwt: true
  # idor: true
  # graphql: true
  # csrf: true
  # cookie-audit: true
  # proto-pollution: true
  # deserialize: true
  # cache-poison: true
  # smuggling: true
  # dom-audit: true
  # dom: true
  # ldap-xpath: true
  # h2c: true
  # jarm: true
  # mass-assign: true
  # axfr: true
  # subdomain-enum: true
  # subdomain-takeover: true
  # ws: true
  # waf-detect: true
  # rate-limit-test: true
  # templates: true

# engine-level tuning (matches module.xray.yaml role). Optional — defaults in code.
engine:
  # max query-variant pages crawled per path before dedup (default 10)
  # max-query-variants: 10
  # WebSocket / TE.TE smuggling deadline override in seconds (0 = use --timeout)
  # handshake-timeout: 0
  # fraction of SLEEP(n) required to flag a time-based delay (default 0.7)
  # sqli-margin-factor: 0.7
  # fraction of confirm SLEEP(n) required to confirm a finding (default 0.6)
  # sqli-confirm-factor: 0.6

flags:
  # free-form flag overrides, e.g.:
  # crawl: "true"
  # threads: "5"
  # timeout: "30"
  # delay: "100"
  # rate-limit: "10"
  # max-pages: "0"
  # blind: "true"
`
	return os.WriteFile(path, []byte(tmpl), 0o644)
}

func FindIn(dir string) string {
	for _, name := range []string{MasterFile, "sxel.yaml", "sxel.yml", ".sxel.yml"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func Find() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return FindIn(wd)
}

func (f *File) FlagValues() map[string]string {
	out := map[string]string{}
	set := func(name, val string) {
		if val != "" {
			out[name] = val
		}
	}
	set("wordlist", f.Wordlist)
	set("cookie", f.Cookie)
	set("scope", f.Scope)
	set("out-of-scope", f.OutOfScope)
	set("exclude", f.Exclude)
	set("proxy", f.Proxy)
	set("user-agent", f.UserAgent)
	set("client-cert", f.ClientCert)
	set("client-key", f.ClientKey)
	set("html-output", f.Report.HTML)
	set("json-output", f.Report.JSON)
	set("csv-output", f.Report.CSV)
	set("md-output", f.Report.MD)
	set("evidence-dir", f.Report.EvidenceDir)
	if f.RateLimit != nil {
		out["rate-limit"] = strconv.Itoa(*f.RateLimit)
	}
	if f.Threads != nil {
		out["threads"] = strconv.Itoa(*f.Threads)
	}
	if f.Timeout != nil {
		out["timeout"] = strconv.Itoa(*f.Timeout)
	}
	if f.Delay != nil {
		out["delay"] = strconv.Itoa(*f.Delay)
	}
	if f.MaxPages != nil {
		out["max-pages"] = strconv.Itoa(*f.MaxPages)
	}
	for name, val := range f.Modules {
		out[name] = fmt.Sprintf("%v", val)
	}
	for name, val := range f.Flags {
		out[name] = val
	}
	return out
}

func ProfileFlags(name string) (map[string]string, bool) {
	switch name {
	case "quick":
		return map[string]string{
			"crawl":            "true",
			"header-scan":      "true",
			"cookie-scan":      "true",
			"security-headers": "true",
			"cookie-audit":     "true",
			"csrf":             "true",
			"open-redirect":    "true",
			"http-methods":     "true",
			"lfi":              "true",
			"cmdi":             "true",
			"ssrf":             "true",
			"nosql":            "true",
			"idor":             "true",
			"cors":             "true",
			"ssti":             "true",
			"crlf":             "true",
			"hpp":              "true",
			"json-injection":   "true",
			"ws":               "true",
			"js-endpoints":     "true",
			"robots":           "true",
		}, true
	case "deep":
		return map[string]string{
			"all":                "true",
			"crawl":              "true",
			"blind":              "true",
			"dom-audit":          "true",
			"js-crawl":           "true",
			"dirscan":            "true",
			"subdomain-enum":     "true",
			"subdomain-takeover": "true",
			"waf-detect":         "true",
			"rate-limit-test":    "true",
			"breach":             "true",
			"strobe":             "true",
			"grpc":               "true",
			"smuggling":          "true",
			"cache-poison":       "true",
			"waf-bypass":         "true",
		}, true
	case "snipe":
		return map[string]string{
			"snipe":      "true",
			"blind":      "true",
			"waf-bypass": "true",
			"rate-limit": "0",
			"dom-audit":  "true",
			"crawl":      "false",
		}, true
	case "thinkphp", "struts2", "shiro", "weblogic", "log4j", "fastjson", "xstream":
		frameworkCore := map[string]string{
			"crawl":          "true",
			"sqli":           "true",
			"xss":            "true",
			"cmdi":           "true",
			"path-traversal": "true",
			"file-upload":    "true",
			"webshell":       "true",
			"waf-detect":     "true",
			"waf-bypass":     "true",
			"blind":          "true",
		}
		frameworkCore["poc"] = name
		return frameworkCore, true
	}
	return nil, false
}

func ValidProfiles() []string {
	return []string{"quick", "deep", "snipe", "thinkphp", "struts2", "shiro", "weblogic", "log4j", "fastjson", "xstream"}
}

func ProfileSummary(name string) string {
	switch name {
	case "quick":
		return "fast passive modules + shallow crawl (no timing/DOM/heavy scans)"
	case "deep":
		return "every module, crawl + JS render + timing + dirscan + recon"
	case "snipe":
		return "single-endpoint deep-dive with simultaneous module attacks"
	case "thinkphp", "struts2", "shiro", "weblogic", "log4j", "fastjson", "xstream":
		return "framework profile: core modules + --poc " + name
	}
	return "unknown profile"
}
