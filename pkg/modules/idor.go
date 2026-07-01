package modules

import (
	"github.com/SentinelXofficial/sxel/pkg/core"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var numericRe = regexp.MustCompile(`^\d{1,12}$`)

// idorParam holds one candidate ID parameter discovered in a URL.
type idorParam struct {
	name    string // query-param name, or "__seg_N__" for path segments
	value   string // the original numeric string value
	inQuery bool   // true = query param, false = path segment
}

// ScanIDOR detects potential Insecure Direct Object Reference vulnerabilities
// by identifying numeric ID parameters in URL query strings and path segments,
// then probing adjacent IDs and comparing HTTP responses.
//
// A potential IDOR is flagged when:
//   - A different ID returns HTTP 200 with significantly different content
//   - An ID that originally returned 403/401 returns 200 with a probe ID
//
// NOTE: IDOR detection is most reliable when --cookie supplies a valid session
// so the scanner can distinguish access-control gaps from missing-record 404s.
func ScanIDOR(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	var candidates []idorParam

	// ── 1. Query-string numeric params ────────────────────────────────────
	qparams, _ := url.ParseQuery(parsed.RawQuery)
	for name, vals := range qparams {
		if len(vals) > 0 && numericRe.MatchString(vals[0]) {
			candidates = append(candidates, idorParam{name: name, value: vals[0], inQuery: true})
		}
	}

	// ── 2. Path-segment numeric values (/user/123, /orders/456) ───────────
	segments := strings.Split(parsed.Path, "/")
	for i, seg := range segments {
		if numericRe.MatchString(seg) {
			candidates = append(candidates, idorParam{
				name:    fmt.Sprintf("__seg_%d__", i),
				value:   seg,
				inQuery: false,
			})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// ── Baseline: original response ───────────────────────────────────────
	origBody, origStatus, err := core.DoGET(client, cfg, target.URL)
	if err != nil {
		return nil
	}

	for _, c := range candidates {
		origID, err := strconv.Atoi(c.value)
		if err != nil {
			continue
		}

		probeIDs := idorAdjacentIDs(origID)

		for _, probeID := range probeIDs {
			if probeID <= 0 {
				continue
			}

			testURL := idorBuildURL(target.URL, parsed, segments, c, probeID)
			if testURL == "" || testURL == target.URL {
				continue
			}

			testBody, testStatus, err := core.DoGET(client, cfg, testURL)
			if err != nil {
				continue
			}

			// Proper access-control responses — not IDOR
			if testStatus == 401 || testStatus == 403 || testStatus == 404 {
				continue
			}

			label := idorFriendlyName(c.name, c.value)

			// Case A: original denied, probe succeeded (clear auth bypass)
			if testStatus == 200 && (origStatus == 403 || origStatus == 401) {
				results = append(results, core.ScanResult{
					Type:      "IDOR (Insecure Direct Object Reference)",
					URL:       testURL,
					Method:    "GET",
					Parameter: label,
					Payload:   strconv.Itoa(probeID),
					Severity:  "HIGH",
					Evidence:  fmt.Sprintf("ID %d→%d: status %d→%d (access-control bypassed)", origID, probeID, origStatus, testStatus),
					Timestamp: time.Now(),
				})
				fmt.Printf("  \033[31m[✗ IDOR]\033[0m %s param=%s id %d→%d status %d→%d\n",
					target.URL, label, origID, probeID, origStatus, testStatus)
				break
			}

			// Case B: both 200 but different content suggests a different record was returned
			if testStatus == 200 && origStatus == 200 {
				diff := idorBodyDiff(origBody, testBody)
				if diff > 100 && !strings.EqualFold(origBody, testBody) {
					results = append(results, core.ScanResult{
						Type:      "IDOR (Insecure Direct Object Reference)",
						URL:       testURL,
						Method:    "GET",
						Parameter: label,
						Payload:   strconv.Itoa(probeID),
						Severity:  "HIGH",
						Evidence:  fmt.Sprintf("ID %d→%d: HTTP 200, body diff=%d bytes (different record returned without ownership check)", origID, probeID, diff),
						Timestamp: time.Now(),
					})
					fmt.Printf("  \033[31m[✗ IDOR]\033[0m %s param=%s id %d→%d diff=%d bytes\n",
						target.URL, label, origID, probeID, diff)
					break
				}
			}
		}
	}

	return results
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func idorAdjacentIDs(id int) []int {
	raw := []int{id + 1, id - 1, id + 100, 1, 2, 999}
	var out []int
	seen := map[int]bool{id: true}
	for _, v := range raw {
		if v > 0 && !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

func idorBuildURL(rawURL string, parsed *url.URL, segments []string, c idorParam, newID int) string {
	if c.inQuery {
		u, err := core.SetParam(rawURL, c.name, strconv.Itoa(newID))
		if err != nil {
			return ""
		}
		return u
	}
	// Path segment replacement
	var segIdx int
	n, _ := fmt.Sscanf(c.name, "__seg_%d__", &segIdx)
	// Sscanf may return io.EOF even on success in some Go versions.
	// Verify we actually parsed one value AND the index is within bounds.
	if n != 1 || segIdx < 0 || segIdx >= len(segments) {
		return ""
	}
	newSegs := make([]string, len(segments))
	copy(newSegs, segments)
	newSegs[segIdx] = strconv.Itoa(newID)
	u := *parsed
	u.Path = strings.Join(newSegs, "/")
	return u.String()
}

func idorFriendlyName(name, value string) string {
	if strings.HasPrefix(name, "__seg_") {
		return "path[" + value + "]"
	}
	return name
}

func idorBodyDiff(a, b string) int {
	d := len(a) - len(b)
	if d < 0 {
		return -d
	}
	return d
}
