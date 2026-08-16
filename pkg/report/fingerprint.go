package report

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

type Finding struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Method    string `json:"method"`
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Severity  string `json:"severity"`
	Evidence  string `json:"evidence"`
	Timestamp string `json:"timestamp"`
}

func FromScanResults(results []core.ScanResult) []Finding {
	out := make([]Finding, 0, len(results))
	for _, r := range results {
		out = append(out, Finding{
			Type: r.Type, URL: r.URL, Method: r.Method,
			Parameter: r.Parameter, Payload: r.Payload,
			Severity: r.Severity, Evidence: r.Evidence,
			Timestamp: r.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	return out
}

var wsRe = regexp.MustCompile(`\s+`)

func NormalizePayload(p string) string {
	p = strings.TrimSpace(p)
	p = wsRe.ReplaceAllString(p, " ")
	return strings.ToLower(p)
}

func Fingerprint(f Finding) string {
	raw := strings.Join([]string{
		strings.ToUpper(f.Method),
		f.URL,
		f.Parameter,
		f.Type,
		NormalizePayload(f.Payload),
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func FingerprintMap(fs []Finding) map[string]Finding {
	out := make(map[string]Finding, len(fs))
	for _, f := range fs {
		out[Fingerprint(f)] = f
	}
	return out
}

func Dedupe(fs []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range fs {
		fp := Fingerprint(f)
		if !seen[fp] {
			seen[fp] = true
			out = append(out, f)
		}
	}
	return out
}
