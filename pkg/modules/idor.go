package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var numericRe = regexp.MustCompile(`^\d{1,12}$`)

type idorParam struct {
	name    string
	value   string
	inQuery bool
}

func ScanIDOR(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	var candidates []idorParam

	qparams, _ := url.ParseQuery(parsed.RawQuery)
	for name, vals := range qparams {
		if len(vals) > 0 && numericRe.MatchString(vals[0]) {
			candidates = append(candidates, idorParam{name: name, value: vals[0], inQuery: true})
		}
	}

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

	origBody, origStatus, err := core.DoGET(client, cfg, target.URL)
	if err != nil {
		return nil
	}

	origBody2, _, err := core.DoGET(client, cfg, target.URL)
	if err != nil {
		return nil
	}
	jitterDiff := idorBodyDiff(origBody, origBody2)
	jitterTokens := idorTokenDiff(origBody, origBody2)

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

			if testStatus == 401 || testStatus == 403 || testStatus == 404 {
				continue
			}

			label := idorFriendlyName(c.name, c.value)

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
				break
			}

			if testStatus == 200 && origStatus == 200 && cfg.Cookie != "" {
				diff := idorBodyDiff(origBody, testBody)
				tokenDiff := idorTokenDiff(origBody, testBody)
				if diff <= jitterDiff && tokenDiff <= jitterTokens {
					continue
				}
				if (diff > 100 || tokenDiff >= 5) && !strings.EqualFold(origBody, testBody) {
					results = append(results, core.ScanResult{
						Type:      "IDOR (Insecure Direct Object Reference)",
						URL:       testURL,
						Method:    "GET",
						Parameter: label,
						Payload:   strconv.Itoa(probeID),
						Severity:  "HIGH",
						Evidence:  fmt.Sprintf("ID %d→%d: HTTP 200, body diff=%d bytes / %d distinct tokens (different record returned without ownership check)", origID, probeID, diff, tokenDiff),
						Timestamp: time.Now(),
					})
					break
				}
			}
		}
	}

	return results
}

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
	var segIdx int
	n, _ := fmt.Sscanf(c.name, "__seg_%d__", &segIdx)
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

func idorTokenDiff(a, b string) int {
	unique := map[string]bool{}
	for _, t := range strings.Fields(a) {
		unique[t] = true
	}
	other := map[string]bool{}
	for _, t := range strings.Fields(b) {
		other[t] = true
	}
	count := 0
	for t := range unique {
		if !other[t] {
			count++
		}
	}
	for t := range other {
		if !unique[t] {
			count++
		}
	}
	return count
}
