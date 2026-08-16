package recon

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type Options struct {
	Target      string
	Active      bool
	Wordlist    []string
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	UserAgent   string
	Probe       bool
	Favicon     bool
}

type LiveHost struct {
	URL     string
	Host    string
	Port    int
	Status  int
	Title   string
	Server  string
	Tech    []string
	Favicon string
}

type Result struct {
	Domain     string
	Subdomains []string
	Live       []LiveHost
	Wildcard   bool
}

func DefaultPorts() []int {
	return []int{80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
}

func Run(opts Options) (*Result, error) {
	domain := HostFromTarget(opts.Target)
	res := &Result{Domain: domain}

	var wc bool
	var subs []string

	client := &http.Client{Timeout: opts.Timeout}
	if client.Timeout == 0 {
		client.Timeout = 10 * time.Second
	}

	isIP := net.ParseIP(strings.Trim(domain, "[]")) != nil
	if !isIP {
		subs = append(subs, PassiveSubdomains(client, domain)...)
	}
	res.Subdomains = append(res.Subdomains, subs...)

	if opts.Active {
		words := opts.Wordlist
		if len(words) == 0 {
			words = BuiltinWordlist()
		}
		wc = wildcardDNS(domain)
		res.Wildcard = wc
		brute := BruteSubdomains(domain, words, wc, opts.Concurrency)
		res.Subdomains = append(res.Subdomains, brute...)
	}

	seen := map[string]bool{}
	deduped := make([]string, 0, len(res.Subdomains))
	for _, s := range res.Subdomains {
		s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "*."), ".")))
		if s == "" || s == domain || seen[s] {
			continue
		}
		seen[s] = true
		deduped = append(deduped, s)
	}
	res.Subdomains = deduped

	hosts := make([]string, 0, len(deduped)+1)
	hosts = append(hosts, domain)
	hosts = append(hosts, deduped...)

	ports := opts.Ports
	if len(ports) == 0 {
		ports = DefaultPorts()
	}

	if opts.Concurrency <= 0 {
		opts.Concurrency = 30
	}

	type openPort struct {
		host string
		port int
	}
	var mu sync.Mutex
	var open []openPort

	g := &errgroup.Group{}
	g.SetLimit(opts.Concurrency)
	for _, h := range hosts {
		h := h
		for _, p := range ports {
			p := p
			g.Go(func() error {
				if PortOpen(h, p, opts.Timeout) {
					mu.Lock()
					open = append(open, openPort{h, p})
					mu.Unlock()
				}
				return nil
			})
		}
	}
	g.Wait()

	if opts.Probe {
		probes := make([]string, 0, len(open))
		for _, op := range open {
			host := op.host
			if net.ParseIP(host) != nil && strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
			for _, scheme := range schemeForPort(op.port) {
				probes = append(probes, scheme+"://"+host+":"+itoa(op.port)+"/")
			}
		}
		pclient := &http.Client{Timeout: opts.Timeout}
		pclient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		if pclient.Timeout == 0 {
			pclient.Timeout = 10 * time.Second
		}
		var live []LiveHost
		liveMap := make(map[string]LiveHost)
		pg := &errgroup.Group{}
		pg.SetLimit(opts.Concurrency)
		for _, u := range probes {
			u := u
			pg.Go(func() error {
				lh, err := ProbeHost(pclient, u, opts.UserAgent, opts.Favicon)
				if err == nil && lh.Status > 0 {
					key := lh.Host + ":" + itoa(lh.Port)
					mu.Lock()
					if prev, ok := liveMap[key]; !ok || (strings.HasPrefix(lh.URL, "https://") && !strings.HasPrefix(prev.URL, "https://")) {
						liveMap[key] = lh
					}
					mu.Unlock()
				}
				return nil
			})
		}
		pg.Wait()
		for _, lh := range liveMap {
			live = append(live, lh)
		}
		res.Live = live
	}

	return res, nil
}

func schemeForPort(port int) []string {
	switch port {
	case 443, 8443:
		return []string{"https"}
	case 80, 8000, 8080, 8888, 3000, 5000:
		return []string{"http"}
	}
	return []string{"http", "https"}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
