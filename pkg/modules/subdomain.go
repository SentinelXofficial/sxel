package modules

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/miekg/dns"
)

var builtinSubdomains = []string{
	"www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "ns1", "ns2",
	"dns", "dns1", "dns2", "mx", "mx1", "mx2",
	"admin", "api", "dev", "stage", "staging", "test", "testing",
	"app", "apps", "blog", "cdn", "cloud", "dashboard",
	"demo", "docs", "download", "git", "help", "internal",
	"jenkins", "jira", "kibana", "login", "m", "manage",
	"monitor", "monitoring", "news", "ns", "origin",
	"panel", "partner", "partners", "pay", "payment", "payments",
	"portal", "prod", "production", "remote", "sandbox",
	"secure", "server", "shop", "sso", "static", "stats",
	"status", "support", "survey", "syslog", "uat",
	"upload", "uploads", "vpn", "web", "webmail",
	"wiki", "ws", "www2", "beta", "alpha",
	"gateway", "gw", "lb", "proxy", "cache",
	"auth", "sso", "id", "login", "signup",
	"assets", "images", "img", "media", "video",
	"mobile", "mobi", "search", "data", "db",
}

func EnumerateSubdomains(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult

	host := extractHost(targetURL)
	if host == "" {
		return nil
	}
	host = strings.ToLower(host)

	baseDomain := strings.TrimPrefix(host, "www.")

	seen := map[string]bool{}
	var mu sync.Mutex
	var found []string

	if subs := queryCrtSh(client, baseDomain, cfg); len(subs) > 0 {
		for _, s := range subs {
			s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "*."), ".")))
			if s != "" && !seen[s] {
				seen[s] = true
				found = append(found, s)
			}
		}
		output.Info("subdomain: crt.sh returned %d subdomain(s) for %s", len(found), baseDomain)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)
	wildcard := wildcardDNS(baseDomain)
	if wildcard {
		output.Info("subdomain: %s resolves wildcard DNS — skipping resolve-based brute force (all candidates would be false positives)", baseDomain)
	}
	for _, sub := range builtinSubdomains {
		if wildcard {
			break
		}
		candidate := sub + "." + baseDomain
		mu.Lock()
		dup := seen[candidate]
		mu.Unlock()
		if dup {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			if resolveDNS(name) {
				mu.Lock()
				if !seen[name] {
					seen[name] = true
					found = append(found, name)
				}
				mu.Unlock()
			}
		}(candidate)
	}
	wg.Wait()

	if len(found) == 0 {
		return nil
	}

	for _, sub := range found {
		results = append(results, core.ScanResult{
			Type:      "Subdomain Discovered",
			URL:       sub,
			Method:    "DNS/CT",
			Parameter: "subdomain",
			Payload:   sub,
			Severity:  "INFO",
			Evidence:  fmt.Sprintf("Subdomain %q of %s discovered", sub, baseDomain),
			Timestamp: time.Now(),
		})
	}
	output.Info("Subdomain: %d total subdomain(s) discovered for %s", len(found), baseDomain)
	return results
}

func queryCrtSh(client *http.Client, domain string, cfg *core.Config) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		if cfg.Verbose {
			output.Verbose("[subdomain] crt.sh unreachable: %v", err)
		}
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	b := core.ReadBody(resp.Body)

	var entries []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.Unmarshal([]byte(b), &entries); err != nil {
		return nil
	}

	seen := map[string]bool{}
	var subs []string
	for _, e := range entries {
		lower := strings.ToLower(strings.TrimSpace(e.CommonName))
		if matchesBaseDomain(lower, domain) && !seen[lower] {
			seen[lower] = true
			subs = append(subs, lower)
		}
		for _, nv := range strings.Split(e.NameValue, "\n") {
			nv = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(nv, ".")))
			if matchesBaseDomain(nv, domain) && !seen[nv] {
				seen[nv] = true
				subs = append(subs, nv)
			}
		}
	}
	return subs
}

func matchesBaseDomain(name, domain string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if name == domain {
		return true
	}
	return strings.HasSuffix(name, "."+domain)
}

func wildcardDNS(domain string) bool {
	name := fmt.Sprintf("sxel-check-%d.%s", time.Now().UnixNano()%100000, domain)
	return resolveDNS(name)
}

func resolveDNS(hostname string) bool {
	if addrs, err := net.LookupHost(hostname); err == nil && len(addrs) > 0 {
		return true
	}
	servers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cc.Servers) > 0 {
		port := cc.Port
		if port == "" {
			port = "53"
		}
		servers = make([]string, 0, len(cc.Servers))
		for _, s := range cc.Servers {
			servers = append(servers, net.JoinHostPort(s, port))
		}
	}

	c := &dns.Client{Timeout: 3 * time.Second}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeCNAME} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(hostname), qtype)
		for _, srv := range servers {
			r, _, err := c.Exchange(m, srv)
			if err == nil && r != nil && len(r.Answer) > 0 {
				return true
			}
		}
	}
	return false
}

func extractHost(rawURL string) string {
	if strings.Contains(rawURL, "://") {
		parts := strings.SplitN(rawURL, "://", 2)
		if len(parts) == 2 {
			host := strings.SplitN(parts[1], "/", 2)[0]
			return hostnameOnly(host)
		}
	}
	return rawURL
}

func hostnameOnly(host string) string {
	if i := strings.Index(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			return host[1:i]
		}
		return strings.TrimSuffix(host, "]")
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}
