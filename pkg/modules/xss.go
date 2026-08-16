package modules

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/payload"
)

var htmlEntityReplacer = strings.NewReplacer(
	"&lt;", "<", "&gt;", ">", "&quot;", "\"", "&apos;", "'", "&amp;", "&",
	"&#34;", "\"", "&#39;", "'", "&#x22;", "\"", "&#x27;", "'",
	"&#60;", "<", "&#62;", ">", "&#x3c;", "<", "&#x3e;", ">",
)

func decodeHTMLEntities(s string) string {
	return htmlEntityReplacer.Replace(s)
}

func allIndexOf(hay, needle string) []int {
	if needle == "" {
		return nil
	}
	var out []int
	start := 0
	for {
		i := strings.Index(hay[start:], needle)
		if i < 0 {
			break
		}
		out = append(out, start+i)
		start += i + 1
	}
	return out
}

var urlBearingAttrs = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true,
	"background": true, "poster": true, "data": true, "longdesc": true,
	"codebase": true, "usemap": true, "cite": true,
}

func xssAttrContext(region, lowPld string) (string, bool) {
	eq := strings.LastIndex(region, "=")
	if eq < 0 {
		return "html attribute", true
	}
	name := strings.TrimSpace(region[:eq])
	if i := strings.LastIndexAny(name, " \t\n\r"); i >= 0 {
		name = strings.TrimSpace(name[i+1:])
	}
	name = strings.ToLower(name)
	if len(name) > 2 && strings.HasPrefix(name, "on") {
		return "event handler attribute", true
	}
	if name == "srcdoc" {
		return "srcdoc attribute", true
	}
	quoteAt := -1
	if i := strings.Index(lowPld, "\""); i >= 0 {
		quoteAt = i
	}
	if i := strings.Index(lowPld, "'"); i >= 0 && (quoteAt < 0 || i < quoteAt) {
		quoteAt = i
	}
	if quoteAt < 0 {
		return "attribute value", false
	}
	after := strings.TrimLeft(lowPld[quoteAt+1:], " \t\r\n")
	if strings.HasPrefix(after, ">") {
		return "html attribute", true
	}
	if len(after) > 2 && strings.HasPrefix(after, "on") {
		return "event handler attribute", true
	}
	if urlBearingAttrs[name] && strings.HasPrefix(after, "javascript:") {
		return "html attribute", true
	}
	return "attribute value", false
}

func contextAt(buf, lowPld string, idx int) (string, bool) {
	pre := buf[:idx]

	if c := strings.LastIndex(pre, "<!--"); c >= 0 && strings.Index(pre[c:], "-->") < 0 {
		return "html comment", false
	}
	for _, tag := range []string{"<title", "<textarea", "<noscript", "<xmp", "<plaintext", "<style"} {
		if o := strings.LastIndex(pre, tag); o >= 0 && strings.Index(pre[o:], "</"+tag[1:]) < 0 {
			if strings.Contains(lowPld, "</"+tag[1:]) {
				return "inert tag breakout", true
			}
			return "inert tag content", false
		}
	}
	scriptOpen := strings.LastIndex(pre, "<script")
	if scriptOpen >= 0 {
		closeAt := strings.Index(pre[scriptOpen:], "</script")
		inBlock := closeAt < 0 || scriptOpen+closeAt >= idx
		if inBlock {
			if strings.Contains(lowPld, "</script") {
				return "script block breakout", true
			}
			if strings.Contains(lowPld, "${") {
				return "script template literal", true
			}
			return "script text", false
		}
	}

	quoteChar := byte(0)
	quoteIdx := -1
	for i := idx - 1; i >= 0; i-- {
		if pre[i] == '"' || pre[i] == '\'' {
			bs := 0
			for j := i - 1; j >= 0 && pre[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 1 {
				continue
			}
			quoteChar = pre[i]
			quoteIdx = i
			break
		}
		if pre[i] == '>' {
			break
		}
	}
	if quoteChar != 0 {
		region := pre[:quoteIdx+1]
		if tagOpen := strings.LastIndex(pre, "<"); tagOpen >= 0 && tagOpen < quoteIdx {
			region = pre[tagOpen : quoteIdx+1]
		}
		if strings.Contains(region, "=") {
			return xssAttrContext(region, lowPld)
		}
	}
	tagOpen := strings.LastIndex(pre, "<")
	if tagOpen >= 0 {
		region := pre[tagOpen:]
		if strings.Contains(region, "=") && !strings.Contains(region, ">") && !strings.Contains(region, "/>") {
			if lastEq := strings.LastIndex(region, "="); lastEq >= 0 {
				fields := strings.Fields(region[:lastEq])
				if len(fields) > 0 && strings.HasPrefix(strings.ToLower(fields[len(fields)-1]), "on") {
					return "event handler attribute", true
				}
			}
			return "html attribute", true
		}
	}
	return "text node", true
}

func contextRank(ctx string, exec bool) int {
	if !exec {
		return 0
	}
	switch ctx {
	case "script block breakout", "script template literal",
		"event handler attribute", "srcdoc attribute":
		return 3
	case "html attribute":
		return 2
	default:
		return 1
	}
}

func analyzeXSSContext(body, pld string) (string, bool) {
	lowBody := strings.ToLower(body)
	lowPld := strings.ToLower(pld)

	bestCtx := ""
	bestRank := 0
	for _, i := range allIndexOf(lowBody, lowPld) {
		ctx, exec := contextAt(lowBody, lowPld, i)
		if r := contextRank(ctx, exec); r > bestRank {
			bestCtx = ctx
			bestRank = r
		}
	}
	if bestRank > 0 {
		return bestCtx, true
	}

	dec := decodeHTMLEntities(lowBody)
	for _, i := range allIndexOf(dec, lowPld) {
		ctx, exec := contextAt(dec, lowPld, i)
		if exec && ctx == "html attribute" {
			return "html attribute (entity breakout)", true
		}
	}
	return "", false
}

func hasReflection(body, pld string) bool {
	if strings.Contains(strings.ToLower(body), strings.ToLower(pld)) {
		return true
	}
	return strings.Contains(strings.ToLower(decodeHTMLEntities(body)), strings.ToLower(pld))
}

func xssFinding(body, pld, testURL, param, method string) core.ScanResult {
	ctx, exec := analyzeXSSContext(body, pld)
	if !exec {
		if ctx == "" {
			return core.ScanResult{}
		}
		return core.ScanResult{
			Type: "Reflected input", URL: testURL,
			Method: method, Parameter: param, Payload: pld,
			Severity: "LOW", Evidence: "reflected in inert context (" + ctx + ")",
			Timestamp: time.Now(),
		}
	}
	sev := "MEDIUM"
	if contextRank(ctx, true) >= 3 {
		sev = "HIGH"
	}
	return core.ScanResult{
		Type: "XSS (Reflected)", URL: testURL,
		Method: method, Parameter: param, Payload: pld,
		Severity: sev, Evidence: "payload reflected in executable context (" + ctx + ")",
		Timestamp: time.Now(),
	}
}

func severityRank(sev string) int {
	switch sev {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	}
	return 0
}

func worstOf(cand core.ScanResult, curr core.ScanResult, rank int) (core.ScanResult, int) {
	if r := severityRank(cand.Severity); r > rank {
		return cand, r
	}
	return curr, rank
}

func ScanXSS(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	var params url.Values
	p, err := url.Parse(target.URL)
	if err == nil {
		params, _ = url.ParseQuery(p.RawQuery)
	} else {
		params = url.Values{}
	}
	for param := range params {
		if cfg.Verbose {
			output.Verbose("[xss-get] param=%s", param)
		}
		var best core.ScanResult
		bestRank := 0
		for _, base := range payload.XSSPayloads {
			variants := []string{base}
			if cfg.WAFBypass {
				variants = WAFBypassXSS(base)
			}
			for _, pld := range variants {
				testURL, err := core.SetParamRaw(target.URL, param, pld)
				if err != nil {
					continue
				}
				body, _, err := core.DoGET(client, cfg, testURL)
				if err != nil {
					continue
				}
				if hasReflection(body, pld) {
					best, bestRank = worstOf(xssFinding(body, pld, testURL, param, "GET"), best, bestRank)
				}
			}
		}
		if bestRank > 0 {
			results = append(results, best)
		}
	}

	for _, form := range target.Forms {
		for _, inp := range form.Inputs {
			if cfg.Verbose {
				output.Verbose("[xss-form] %s field=%s", form.Action, inp.Name)
			}
			var best core.ScanResult
			bestRank := 0
			for _, base := range payload.XSSPayloads {
				variants := []string{base}
				if cfg.WAFBypass {
					variants = WAFBypassXSS(base)
				}
				for _, pld := range variants {
					var body string
					var err error
					if form.Method == "POST" {
						d := core.FormDefaults(form)
						d.Set(inp.Name, pld)
						body, _, err = core.DoPOST(client, cfg, form.Action, d)
					} else {
						d := core.FormDefaults(form)
						d.Set(inp.Name, pld)
						testURL, _ := core.SetFormParams(form.Action, d)
						body, _, err = core.DoGET(client, cfg, testURL)
					}
					if err != nil {
						continue
					}
					if hasReflection(body, pld) {
						best, bestRank = worstOf(xssFinding(body, pld, form.Action, inp.Name, form.Method), best, bestRank)
					}
				}
			}
			if bestRank > 0 {
				results = append(results, best)
			}
		}
	}
	return results
}
