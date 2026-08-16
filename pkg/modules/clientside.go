package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

var (
	domSinkRe        = regexp.MustCompile(`(?i)(innerHTML|outerHTML|insertAdjacentHTML|document\.write|writeln|eval\s*\(|new Function|setAttribute\s*\(\s*["']?(on\w+|href|src))`)
	domSourceRe      = regexp.MustCompile(`(?i)(location\.hash|location\.search|location\.pathname|document\.URL|document\.location|document\.referrer|URLSearchParams|window\.name|postMessage\(|addEventListener\s*\(\s*["']message["'])`)
	domNoOriginRe    = regexp.MustCompile(`(?i)addEventListener\s*\(\s*["']message["']`)
	domOriginCheckRe = regexp.MustCompile(`(?i)(event\.origin|e\.origin|\.origin\s*[!=]==)`)
	scriptSrcRe      = regexp.MustCompile(`(?i)src=["']([^"']+\.js(?:\?[^"']*)?)["']`)
	scriptBlockRe    = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
)

func ScanDOMAudit(client *http.Client, cfg *core.Config, pageURL string) []core.ScanResult {
	var results []core.ScanResult

	body, _, err := core.DoGET(client, cfg, pageURL)
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var scripts []string
	for _, m := range scriptBlockRe.FindAllStringSubmatch(body, -1) {
		scripts = append(scripts, m[1])
	}
	base, _ := url.Parse(pageURL)
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		src := m[1]
		var full string
		if strings.HasPrefix(strings.ToLower(src), "http://") || strings.HasPrefix(strings.ToLower(src), "https://") {
			full = src
		} else if strings.HasPrefix(src, "/") {
			if ref, err := url.Parse(src); err == nil {
				full = base.ResolveReference(ref).String()
			}
		}
		if full == "" || seen[full] {
			continue
		}
		seen[full] = true
		srcBody, _, err := core.DoGET(client, cfg, full)
		if err != nil || len(srcBody) > 512*1024 {
			continue
		}
		scripts = append(scripts, srcBody)
	}

	for idx, s := range scripts {
		if len(scripts) > 1 {
			s = s[:min(len(s), 256*1024)]
		}
		sink := domSinkRe.MatchString(s)
		source := domSourceRe.MatchString(s)
		if sink && source {
			results = append(results, core.ScanResult{
				Type: "DOM XSS candidate (static)", URL: pageURL,
				Method: "GET", Parameter: "script",
				Payload:  "sink + taint source pair",
				Severity: "LOW", Evidence: fmt.Sprintf("script #%d contains sink and source keywords", idx+1),
				Timestamp: time.Now(),
			})
			fmt.Printf("  [DOM-AUDIT] %s script #%d sink+source\n", pageURL, idx+1)
		}
		if domNoOriginRe.MatchString(s) && !domOriginCheckRe.MatchString(s) {
			results = append(results, core.ScanResult{
				Type: "postMessage listener without origin check", URL: pageURL,
				Method: "GET", Parameter: "script",
				Payload:  "addEventListener('message')",
				Severity: "MEDIUM", Evidence: fmt.Sprintf("script #%d accepts messages from any origin", idx+1),
				Timestamp: time.Now(),
			})
			fmt.Printf("  [DOM-AUDIT] %s script #%d postMessage no origin check\n", pageURL, idx+1)
		}
	}
	return results
}
