package modules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

var massAssignFields = []string{
	"is_admin", "admin", "isAdmin", "role", "is_verified", "email_verified",
	"verified", "approved", "status", "permission", "permissions", "balance",
	"vip", "trial_end", "plan", "subscription", "can_upload", "is_premium",
}

type massProbe struct {
	url      string
	baseKeys []string
}

func collectJSONProbes(client *http.Client, cfg *core.Config, targetURL string) []massProbe {
	var probes []massProbe
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}
	core.ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body := core.ReadBody(resp.Body)
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	resp.Body.Close()
	isJSON := strings.Contains(ct, "json") || strings.HasPrefix(strings.TrimSpace(body), "{")
	if !isJSON {
		return probes
	}
	var doc map[string]any
	if json.Unmarshal([]byte(body), &doc) != nil {
		return probes
	}
	var keys []string
	for k := range doc {
		keys = append(keys, k)
		if len(keys) >= 10 {
			break
		}
	}
	if len(keys) > 0 {
		probes = append(probes, massProbe{url: targetURL, baseKeys: keys})
	}
	return probes
}

func massPost(client *http.Client, cfg *core.Config, url string, extra map[string]any) (string, int, error) {
	obj := map[string]any{}
	for k, v := range extra {
		obj[k] = v
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return "", 0, err
	}
	return core.DoJSONPOST(client, cfg, url, string(raw))
}

func bodyFingerprint(b string) string {
	var doc map[string]any
	if json.Unmarshal([]byte(b), &doc) == nil {
		return fmt.Sprintf("%d:%s", len(b), strings.Join(sortedKeys(doc), ","))
	}
	return fmt.Sprintf("%d", len(b))
}

func sortedKeys(doc map[string]any) []string {
	var ks []string
	for k := range doc {
		ks = append(ks, k)
	}
	for i := 0; i < len(ks); i++ {
		for j := i + 1; j < len(ks); j++ {
			if ks[j] < ks[i] {
				ks[i], ks[j] = ks[j], ks[i]
			}
		}
	}
	return ks
}

func ScanMassAssignment(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult
	probes := collectJSONProbes(client, cfg, target.URL)
	for _, pr := range probes {
		baseBody, baseStatus, err1 := massPost(client, cfg, pr.url, nil)
		garbBody, _, err2 := massPost(client, cfg, pr.url, map[string]any{"zz_sxel_garbage_921": true})
		garbBody2, _, err3 := massPost(client, cfg, pr.url, map[string]any{"zz_sxel_garbage_921": true})
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		if bodyFingerprint(baseBody) != bodyFingerprint(garbBody) || bodyFingerprint(garbBody) != bodyFingerprint(garbBody2) {
			continue
		}
		for _, field := range massAssignFields {
			probeBody, probeStatus, err := massPost(client, cfg, pr.url, map[string]any{field: true})
			if err != nil {
				continue
			}
			if bodyFingerprint(probeBody) == bodyFingerprint(baseBody) && probeStatus == baseStatus {
				continue
			}
			if bodyFingerprint(probeBody) == bodyFingerprint(garbBody) && probeStatus == baseStatus {
				continue
			}
			ev := fmt.Sprintf("server response changed when field %q was added (HTTP %d -> %d)", field, baseStatus, probeStatus)
			if strings.Contains(strings.ToLower(probeBody), strings.ToLower(field)) {
				ev += "; field name reflected in response"
			}
			results = append(results, core.ScanResult{
				Type: "Mass assignment candidate", URL: pr.url,
				Method: "POST/JSON", Parameter: field, Payload: fmt.Sprintf("{%q:true}", field),
				Severity: "MEDIUM", Evidence: ev, Timestamp: time.Now(),
			})
			fmt.Printf("  [MASS-ASSIGN] %s field=%s\n", pr.url, field)
			break
		}
	}
	return results
}
