package modules

import (
	"encoding/json"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Built-in common subdomains for DNS brute-force when crt.sh is unavailable.
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

// EnumerateSubdomains discovers subdomains via crt.sh (Certificate Transparency
// logs) and falls back to DNS brute-force if the API is unreachable.
func EnumerateSubdomains(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult

	host := extractHost(targetURL)
	if host == "" {
		return nil
	}

	// Remove leading "www." to get the base domain
	baseDomain := strings.TrimPrefix(host, "www.")

	seen := map[string]bool{}
	var found []string

	// ── 1. Try crt.sh (free, no auth required) ────────────────────────
	if subs := queryCrtSh(baseDomain, cfg); len(subs) > 0 {
		for _, s := range subs {
			s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "*."), "."))
			if s != "" && !seen[s] {
				seen[s] = true
				found = append(found, s)
			}
		}
		fmt.Printf("  [subdomain] crt.sh returned %d subdomain(s) for %s\n", len(found), baseDomain)
	}

	// ── 2. DNS brute-force (always run as a supplement) ───────────────
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 20) // DNS lookups are cheap
	for _, sub := range builtinSubdomains {
		candidate := sub + "." + baseDomain
		if seen[candidate] {
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
	output.Info("[*] Subdomain   : %d total subdomain(s) discovered for %s\n", len(found), baseDomain)
	return results
}

// queryCrtSh fetches subdomain entries from crt.sh for the given domain.
func queryCrtSh(domain string, cfg *core.Config) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	httpClient := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := httpClient.Do(req)
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

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var entries []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil
	}

	seen := map[string]bool{}
	var subs []string
	for _, e := range entries {
		lower := strings.ToLower(e.CommonName)
		if strings.Contains(lower, strings.ToLower(domain)) && !seen[e.CommonName] {
			seen[e.CommonName] = true
			subs = append(subs, e.CommonName)
		}
		for _, nv := range strings.Split(e.NameValue, "\n") {
			nv = strings.TrimSpace(nv)
			lower := strings.ToLower(nv)
			if strings.Contains(lower, strings.ToLower(domain)) && !seen[nv] {
				seen[nv] = true
				subs = append(subs, nv)
			}
		}
	}
	return subs
}

// resolveDNS returns true if the hostname resolves to an IP address.
func resolveDNS(hostname string) bool {
	// Try A record first
	if addrs, err := net.LookupHost(hostname); err == nil && len(addrs) > 0 {
		return true
	}
	// Try CNAME as fallback
	_, err := net.LookupCNAME(hostname)
	return err == nil
}

// extractHost returns the host part of a URL, stripping the scheme and path.
func extractHost(rawURL string) string {
	if strings.Contains(rawURL, "://") {
		parts := strings.SplitN(rawURL, "://", 2)
		if len(parts) == 2 {
			host := strings.SplitN(parts[1], "/", 2)[0]
			host = strings.SplitN(host, ":", 2)[0] // remove port
			return host
		}
	}
	return rawURL
}
