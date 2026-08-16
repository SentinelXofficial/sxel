package modules

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/miekg/dns"
)

func transferZone(server, zone string) []dns.RR {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))
	if !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "53")
	}
	tr := &dns.Transfer{
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	ch, err := tr.In(m, server)
	if err != nil {
		return nil
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			return nil
		}
		rrs = append(rrs, env.RR...)
	}
	return rrs
}

func candidateZones(host string) []string {
	var zones []string
	zones = append(zones, host)
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		apex := strings.Join(parts[len(parts)-2:], ".")
		zones = append(zones, apex)
	}
	return zones
}

func resolveNS(host string, override string) []string {
	if override != "" {
		return []string{override}
	}
	nss, err := net.LookupNS(host)
	if err != nil {
		return nil
	}
	var servers []string
	for _, ns := range nss {
		server := ns.Host
		if !strings.Contains(server, ":") {
			server = net.JoinHostPort(server, "53")
		}
		servers = append(servers, server)
	}
	return servers
}

func ScanAXFR(client *http.Client, cfg *core.Config, targetURL string, nsOverride string) []core.ScanResult {
	var results []core.ScanResult
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	servers := resolveNS(host, nsOverride)
	if len(servers) == 0 {
		return nil
	}
	for _, zone := range candidateZones(host) {
		for _, server := range servers {
			rrs := transferZone(server, zone)
			if len(rrs) == 0 {
				continue
			}
			var sample []string
			for i, rr := range rrs {
				if i >= 8 {
					break
				}
				sample = append(sample, rr.String())
			}
			results = append(results, core.ScanResult{
				Type: "DNS zone transfer (AXFR)", URL: targetURL,
				Parameter: zone, Severity: "HIGH",
				Evidence: fmt.Sprintf("zone %s transferable from %s; %d records: %s",
					zone, server, len(rrs), strings.Join(sample, ", ")),
				Timestamp: time.Now(),
			})
			fmt.Printf("  [AXFR] zone %s via %s (%d records)\n", zone, server, len(rrs))
			return results
		}
	}
	return results
}
