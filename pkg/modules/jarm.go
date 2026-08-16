package modules

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hdm/jarm-go"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func fingerprintJARM(host string, port int) string {
	var results []string
	for _, probe := range jarm.GetProbes(host, port) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
		if err != nil {
			return ""
		}
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		_, werr := conn.Write(jarm.BuildProbe(probe))
		if werr != nil {
			conn.Close()
			return ""
		}
		buff := make([]byte, 1484)
		n, rerr := conn.Read(buff)
		conn.Close()
		if rerr != nil || n == 0 {
			return ""
		}
		ans, err := jarm.ParseServerHello(buff[:n], probe)
		if err != nil {
			return ""
		}
		results = append(results, ans)
	}
	if strings.Trim(strings.Join(results, ","), ",") == "" {
		return ""
	}
	return jarm.RawHashToFuzzyHash(strings.Join(results, ","))
}

func ScanJARM(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		return nil
	}
	port := 443
	if u.Port() != "" {
		port, _ = strconv.Atoi(u.Port())
	} else if u.Scheme == "http" {
		port = 80
	}
	h := fingerprintJARM(u.Hostname(), port)
	if len(h) != 62 || strings.Trim(h, "0") == "" {
		return nil
	}
	sev := "INFO"
	hint := "unrecognized TLS stack"
	if strings.HasPrefix(h, "1e2e1e") {
		hint = "Go net/http TLS server"
	}
	if strings.HasPrefix(h, "21d19d") {
		hint = "nginx default TLS config"
	}
	if strings.HasPrefix(h, "2ad2ad") {
		hint = "AWS ELB / Cloudflare-class proxy stack"
	}
	if strings.HasPrefix(h, "29d29d") {
		hint = "CDN/proxy default TLS stack"
	}
	finding := core.ScanResult{
		Type: "JARM TLS Fingerprint", URL: targetURL,
		Method: "TCP/TLS", Parameter: "host",
		Payload: h, Severity: sev,
		Evidence:  "JARM hash: " + h + " (" + hint + ")",
		Timestamp: time.Now(),
	}
	fmt.Printf("  [JARM] %s:%d %s (%s)\n", u.Hostname(), port, h, hint)
	return []core.ScanResult{finding}
}
