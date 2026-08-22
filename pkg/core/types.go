package core

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/projectdiscovery/retryablehttp-go"

	"github.com/SentinelXofficial/sxel/internal/output"
)

type Config struct {
	URL         string
	Crawl       bool
	BasicCrawl  bool
	JSCrawl     bool
	Threads     int
	Timeout     int
	WAFBypass   bool
	HTMLOutput  string
	JSONOutput  string
	CSVOutput   string
	EvidenceDir string
	SQLScan     bool
	XSSScan     bool
	Cookie      string
	Headers     map[string]string
	Delay       int
	UserAgent   string
	Proxy       string
	Verbose     bool
	WS          bool
	Exclude     string
	MaxPages    int
	ClientCert  string
	ClientKey   string

	BlindSQLi bool

	MaxQueryVariants  int
	HandshakeTimeout  int
	SQLiMarginFactor  float64
	SQLiConfirmFactor float64
	HeaderScan        bool
	CookieScan        bool
	SensitiveFiles    bool
	OpenRedirect      bool
	PathTraversal     bool
	SecurityHdrs      bool
	CORSScan          bool
	HTTPMethods       bool
	JSEndpoints       bool
	SSTI              bool
	CRLFScan          bool
	HostHeader        bool
	JSONScan          bool
	HPP               bool
	DOMAudit          bool
	LDAPXPath         bool
	H2C               bool
	JARMScan          bool
	DOMXSS            bool
	MassAssign        bool
	AXFR              bool
	AllChecks         bool
	PocScan           bool
	PocNames          string
	PocTags           string
	PocLevel          int
	PocDir            string

	CmdInjection bool
	SSRFScan     bool
	XXEScan      bool
	NoSQLScan    bool

	RateLimit int
	Limiter   *RateLimiter

	Recorder *Recorder
	Session  *SessionJar

	DirScan  bool
	Wordlist string

	Scope      []string
	OutOfScope []string

	WAFAutoDetect bool

	FileUpload bool
	JWTScan    bool
	IDORScan   bool
	GraphQL    bool
	WebShell   bool

	Checkpoint     *CheckpointState
	CheckpointFile string

	CSRF           bool
	CookieAudit    bool
	SubdomainEnum  bool
	ProtoPollution bool
	Deserialize    bool
	CachePoison    bool
	CacheDeception bool
	LFI            bool
	Smuggling      bool
	RateLimitTest  bool
	SubTakeover    bool

	Clutch      bool
	APISecurity bool
	Breach      bool
	Grpc        bool
	Strobe      bool
	Snipe       bool

	Templates   bool
	TemplateDir string

	OOBAddress string

	OOBDomain string

	TemplateSeverity string
}

type ScanResult struct {
	Type       string            `json:"type"`
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Parameter  string            `json:"parameter"`
	Payload    string            `json:"payload"`
	Severity   string            `json:"severity"`
	Evidence   string            `json:"evidence"`
	Timestamp  time.Time         `json:"timestamp"`
	ParamKey   string            `json:"param_key,omitempty"`
	ParamValue string            `json:"param_value,omitempty"`
	Position   string            `json:"position,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
	Request    string            `json:"request,omitempty"`
	Response   string            `json:"response,omitempty"`
}

type Form struct {
	Action     string
	Method     string
	Inputs     []Input
	TokenName  string
	TokenValue string
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

type retryTransport struct {
	rc *retryablehttp.Client
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rreq, err := retryablehttp.FromRequest(req)
	if err != nil {
		return nil, err
	}
	return t.rc.Do(rreq)
}

func (t *retryTransport) Unwrap() http.RoundTripper {
	if t.rc != nil && t.rc.HTTPClient != nil {
		return t.rc.HTTPClient.Transport
	}
	return nil
}

type limiterTransport struct {
	rt  http.RoundTripper
	cfg *Config
}

func (t *limiterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.cfg.Limiter.Wait()
	return t.rt.RoundTrip(req)
}

func (t *limiterTransport) Unwrap() http.RoundTripper { return t.rt }

type decompressTransport struct {
	rt http.RoundTripper
}

func (t *decompressTransport) Unwrap() http.RoundTripper { return t.rt }

func (t *decompressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if resp != nil && resp.Body != nil && strings.Contains(resp.Header.Get("Content-Encoding"), "br") {
		resp.Body = io.NopCloser(brotli.NewReader(resp.Body))
		resp.Header.Del("Content-Encoding")
		resp.ContentLength = -1
	}
	return resp, nil
}

func TLSClientConfigFor(cfg *Config) *tls.Config {
	tc := &tls.Config{InsecureSkipVerify: true}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			output.Warn("invalid client certificate/key: %v — continuing without mTLS", err)
			return tc
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc
}

// BaseTransportFor unwraps the scanner middleware (recorder/retry/limiter/
// decompress) and returns the underlying *http.Transport, or nil if the
// client's chain does not terminate in one.
func BaseTransportFor(c *http.Client) *http.Transport {
	if c == nil {
		return nil
	}
	rt := c.Transport
	for i := 0; i < 8 && rt != nil; i++ {
		if t, ok := rt.(*http.Transport); ok {
			return t
		}
		u, ok := rt.(interface{ Unwrap() http.RoundTripper })
		if !ok {
			return nil
		}
		rt = u.Unwrap()
	}
	return nil
}

func NewHTTPClient(cfg *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: TLSClientConfigFor(cfg),
	}
	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			output.Warn("invalid --proxy %q: %v — proceeding without proxy", cfg.Proxy, err)
		} else {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15
	}
	timeoutDur := time.Duration(timeout) * time.Second
	base := &http.Client{
		Timeout: timeoutDur,
		Transport: &limiterTransport{
			rt:  &decompressTransport{rt: transport},
			cfg: cfg,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	rc := retryablehttp.NewClient(retryablehttp.Options{
		HttpClient:      base,
		RetryMax:        2,
		RetryWaitMin:    250 * time.Millisecond,
		RetryWaitMax:    2 * time.Second,
		Timeout:         timeoutDur,
		NoAdjustTimeout: true,
		CheckRetry: func(_ context.Context, resp *http.Response, err error) (bool, error) {
			if errors.Is(err, ErrRateLimited) {
				return false, nil
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return false, err
			}
			if err != nil {
				return true, nil
			}
			return false, nil
		},
	})
	return &http.Client{
		Transport: &recorderTransport{
			rt:  &retryTransport{rc: rc},
			rec: cfg.Recorder,
		},
		Timeout:       timeoutDur,
		CheckRedirect: base.CheckRedirect,
		Jar:           cfg.Session,
	}
}

type BaselineResult struct {
	Body    string
	BodyLow string
	Length  int
	Status  int
	Valid   bool
}

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
		return resp, err
	}
	if resp != nil && resp.Body != nil && strings.Contains(resp.Header.Get("Content-Encoding"), "br") {
		resp.Body = io.NopCloser(brotli.NewReader(resp.Body))
		resp.Header.Del("Content-Encoding")
		resp.ContentLength = -1
	}
	return resp, err
}

func NewCountingClient(client *http.Client, sent, failed, totalNS *int64) *http.Client {
	tr := client.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	return &http.Client{
		Transport:     &CountingTransport{Base: tr, Sent: sent, Failed: failed, TotalNS: totalNS},
		Timeout:       client.Timeout,
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
	}
}
