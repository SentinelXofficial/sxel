package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

func getJSON(client *http.Client, url string, out interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "sxel-recon")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func getText(client *http.Client, url string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "sxel-recon")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(body)
}

func cleanNames(names []string, domain string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		n = strings.TrimSuffix(n, ".")
		if n == "" {
			continue
		}
		if !matchesDomain(n, domain) {
			continue
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func PassiveSubdomains(client *http.Client, domain string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "www.")
	var all []string

	all = append(all, crtSh(client, domain)...)
	all = append(all, certSpotter(client, domain)...)
	all = append(all, hackerTarget(client, domain)...)
	all = append(all, anubis(client, domain)...)
	all = append(all, otxPassiveDNS(client, domain)...)

	return cleanNames(all, domain)
}

func crtSh(client *http.Client, domain string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := getJSON(client, url, &entries); err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		for _, n := range strings.Split(e.NameValue, "\n") {
			n = strings.TrimSpace(strings.TrimPrefix(n, "*."))
			if n != "" {
				names = append(names, n)
			}
		}
	}
	return names
}

func certSpotter(client *http.Client, domain string) []string {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := getJSON(client, url, &entries); err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.DNSNames...)
	}
	return names
}

func hackerTarget(client *http.Client, domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	text := getText(client, url)
	if text == "" {
		return nil
	}
	var names []string
	for _, line := range strings.Split(text, "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) > 0 {
			names = append(names, parts[0])
		}
	}
	return names
}

func anubis(client *http.Client, domain string) []string {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	var names []string
	if err := getJSON(client, url, &names); err != nil {
		return nil
	}
	return names
}

func otxPassiveDNS(client *http.Client, domain string) []string {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := getJSON(client, url, &resp); err != nil {
		return nil
	}
	var names []string
	for _, p := range resp.PassiveDNS {
		names = append(names, p.Hostname)
	}
	return names
}

func matchesDomain(name, domain string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func HostFromTarget(raw string) string {
	host := raw
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if strings.Contains(host, "]") {
		if i := strings.LastIndex(host, "]"); i >= 0 {
			host = host[:i+1]
		}
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	}
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host, "]") {
		host = host[:i]
	}
	return strings.ToLower(strings.TrimSpace(host))
}
