package core

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

type Config struct {
	URL        string
	Crawl      bool
	BasicCrawl bool
	Depth      int
	Threads    int
	Timeout    int
	WAFBypass  bool
	HTMLOutput string
	JSONOutput string
	CSVOutput  string
	SQLOnly    bool
	XSSOnly    bool
	Cookie     string
	Headers    map[string]string
	Delay      int
	UserAgent  string
	Proxy      string
	Verbose    bool
	WS         bool
	Exclude    string
	MaxPages   int

	// Extended scan modules
	BlindSQLi      bool
	HeaderScan     bool
	CookieScan     bool
	SensitiveFiles bool
	OpenRedirect   bool
	PathTraversal  bool
	SecurityHdrs   bool
	CORSScan       bool
	HTTPMethods    bool
	JSEndpoints    bool
	SSTI           bool
	CRLFScan       bool
	HostHeader     bool
	JSONScan       bool
	AllChecks      bool

	// Sprint 2 — new scan modules
	CmdInjection bool // --cmdi : OS command injection
	SSRFScan     bool // --ssrf : Server-Side Request Forgery
	XXEScan      bool // --xxe  : XML External Entity injection
	NoSQLScan    bool // --nosql: NoSQL (MongoDB) injection

	// Sprint 2 — global rate limiter
	RateLimit int          // --rate-limit N: max N req/sec (0 = no limit)
	Limiter   *RateLimiter // populated at startup if RateLimit > 0

	// Sprint 3 — directory brute force
	DirScan  bool   // --dirscan: run directory brute force
	Wordlist string // --wordlist: path to custom wordlist file

	// Sprint 3 — scope control
	Scope      []string // --scope: patterns that URLs MUST match to be crawled
	OutOfScope []string // --out-of-scope: patterns that EXCLUDE URLs from crawling

	// Sprint 3 — WAF auto-detect
	WAFAutoDetect bool // --waf-detect: probe for WAF before scanning

	// Sprint 4 — new scan modules
	FileUpload bool // --file-upload : test for unrestricted file upload
	JWTScan    bool // --jwt         : test for JWT misconfiguration
	IDORScan   bool // --idor        : test for insecure direct object reference
	GraphQL    bool // --graphql     : test GraphQL endpoints

	// Sprint 4 — resume / checkpoint
	Checkpoint     *CheckpointState // populated when --resume or --checkpoint is set
	CheckpointFile string           // path written to disk after each URL

	// Sprint 5 — new scan modules
	CSRF           bool // --csrf           : test for CSRF vulnerabilities
	CookieAudit    bool // --cookie-audit   : audit cookie security flags
	SubdomainEnum  bool // --subdomain-enum : enumerate subdomains via crt.sh + DNS
	ProtoPollution bool // --proto-pollution: test for prototype pollution in JSON
	Deserialize    bool // --deserialize    : test for insecure deserialization
	CachePoison    bool // --cache-poison   : test for web cache poisoning
	LFI            bool // --lfi            : test for LFI/RFI
	Smuggling      bool // --smuggling      : test for HTTP request smuggling
	RateLimitTest  bool // --rate-limit-test: test rate limiting defenses
	SubTakeover    bool // --subdomain-takeover: check for subdomain takeover

	// Sprint B — new attack modules
	Clutch bool // --clutch  : detect race condition / TOCTOU
	Breach bool // --breach  : probe OAuth + SAML misconfigurations
	Grpc   bool // --grpc    : probe gRPC reflection + REST gateway
	Strobe bool // --strobe  : full adaptive deep-dive pipeline
	Snipe  bool // --snipe   : all modules attack single endpoint simultaneously
}

type ScanResult struct {
	Type       string    `json:"type"`
	URL        string    `json:"url"`
	Method     string    `json:"method"`
	Parameter  string    `json:"parameter"`
	Payload    string    `json:"payload"`
	Severity   string    `json:"severity"`
	Evidence   string    `json:"evidence"`
	Timestamp  time.Time `json:"timestamp"`
	ParamKey   string    `json:"param_key,omitempty"`
	ParamValue string    `json:"param_value,omitempty"`
	Position   string    `json:"position,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

type Form struct {
	Action string
	Method string
	Inputs []Input
}

type Input struct {
	Name  string
	Type  string
	Value string
}

type CrawlResult struct {
	URL   string
	Forms []Form
}

type ScanReport struct {
	Target    string
	StartTime string
	Duration  string
	Results   []ReportEntry
	Stats     ScanStats
}

type ReportEntry struct {
	ScanResult
	CVSS        string
	Remediation string
}

type ScanStats struct {
	TotalURLs   int
	TotalForms  int
	SQLiCount   int
	XSSCount    int
	WSCount     int
	OtherCount  int
	HighCount   int
	MediumCount int
	LowCount    int
	InfoCount   int
}

func NewHTTPClient(cfg *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	if cfg.Proxy != "" {
		if pu, err := url.Parse(cfg.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 // default 15s
	}
	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// BaselineResult holds safe-request baseline data for false positive reduction.
type BaselineResult struct {
	Body    string
	BodyLow string
	Length  int
	Status  int
}

// CountingTransport wraps http.RoundTripper and increments atomic counters.
type CountingTransport struct {
	Base    http.RoundTripper
	Sent    *int64
	Failed  *int64
	TotalNS *int64
}

func (ct *CountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t0 := time.Now()
	atomic.AddInt64(ct.Sent, 1)
	resp, err := ct.Base.RoundTrip(req)
	elapsed := time.Since(t0)
	atomic.AddInt64(ct.TotalNS, int64(elapsed))
	if err != nil {
		atomic.AddInt64(ct.Failed, 1)
	}
	return resp, err
}

// NewCountingClient wraps an existing client with request counting for progress display.
func NewCountingClient(client *http.Client, sent, failed, totalNS *int64) *http.Client {
	tr := client.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	return &http.Client{
		Transport: &CountingTransport{Base: tr, Sent: sent, Failed: failed, TotalNS: totalNS},
		Timeout:   client.Timeout,
		CheckRedirect: client.CheckRedirect,
	}
}

