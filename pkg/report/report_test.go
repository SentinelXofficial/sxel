package report

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestCVSS3ScoreKnownVectors(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
	}
	for _, c := range cases {
		got := CVSS3Score(c.vector)
		if got != c.want {
			t.Errorf("CVSS3Score(%s) = %.1f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestBaseVectorSeverityMapping(t *testing.T) {
	cases := []struct {
		sev, vtype string
		wantScore  float64
	}{
		{"CRITICAL", "SQL Injection", 9.8},
		{"HIGH", "XSS", 8.2},
		{"MEDIUM", "CSRF", 6.5},
		{"LOW", "Cookie Audit", 5.3},
		{"INFO", "Directory Listing", 0},
	}
	for _, c := range cases {
		v := BaseVector(c.sev, c.vtype)
		got := CVSS3Score(v)
		if got != c.wantScore {
			t.Errorf("BaseVector(%s,%s)=%s score=%.1f want %.1f", c.sev, c.vtype, v, got, c.wantScore)
		}
	}
	if got := CVSS3Score(BaseVector("HIGH", "Stored XSS")); got != 9.6 {
		t.Errorf("stored xss vector score = %.1f, want 9.6", got)
	}
}

func TestSeverityFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.8, "CRITICAL"}, {7.5, "HIGH"}, {5.3, "MEDIUM"}, {2.0, "LOW"}, {0, "INFO"},
	}
	for _, c := range cases {
		if got := SeverityFromScore(c.score); got != c.want {
			t.Errorf("SeverityFromScore(%.1f) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestFingerprint(t *testing.T) {
	f1 := Finding{Type: "SQL Injection", URL: "http://x/?id=1", Method: "GET", Parameter: "id", Payload: "' OR 1=1--"}
	f2 := Finding{Type: "SQL Injection", URL: "http://x/?id=1", Method: "GET", Parameter: "id", Payload: "  ' or 1=1--   "}
	f3 := Finding{Type: "XSS", URL: "http://x/?id=1", Method: "GET", Parameter: "id", Payload: "' OR 1=1--"}
	if Fingerprint(f1) != Fingerprint(f2) {
		t.Error("fingerprint should normalize payload whitespace/case")
	}
	if Fingerprint(f1) == Fingerprint(f3) {
		t.Error("different types must have different fingerprints")
	}
}

func TestDedupe(t *testing.T) {
	fs := []Finding{
		{Type: "XSS", URL: "http://x/?a=1", Method: "GET", Parameter: "a", Payload: "<script>"},
		{Type: "XSS", URL: "http://x/?a=1", Method: "GET", Parameter: "a", Payload: "<script>"},
		{Type: "XSS", URL: "http://x/?a=1", Method: "GET", Parameter: "a", Payload: "<SCRIPT>"},
		{Type: "SQL Injection", URL: "http://x/?a=1", Method: "GET", Parameter: "a", Payload: "'"},
	}
	if got := len(Dedupe(fs)); got != 2 {
		t.Errorf("Dedupe = %d, want 2", got)
	}
}

func TestWriteSARIF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	fs := []Finding{
		{Type: "SQL Injection", URL: "http://x/?id=1", Method: "GET", Parameter: "id", Payload: "'", Severity: "HIGH", Evidence: "error in response"},
		{Type: "XSS", URL: "http://x/?q=2", Method: "GET", Parameter: "q", Payload: "<script>", Severity: "MEDIUM", Evidence: "reflected"},
	}
	if err := WriteSARIF(path, fs, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var log map[string]interface{}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("sarif version = %v", log["version"])
	}
	runs := log["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 2 {
		t.Fatalf("sarif results = %d", len(results))
	}
	first := results[0].(map[string]interface{})
	if first["level"] != "error" {
		t.Errorf("high severity should map to error, got %v", first["level"])
	}
	fp := first["partialFingerprints"].(map[string]interface{})
	if _, ok := fp["sxelFingerprint/v1"]; !ok {
		t.Error("partialFingerprints missing")
	}
}

func TestCompare(t *testing.T) {
	prev := []Finding{
		{Type: "XSS", URL: "http://x/?a=1", Method: "GET", Parameter: "a", Payload: "p1", Severity: "HIGH"},
		{Type: "SQL Injection", URL: "http://x/?b=2", Method: "GET", Parameter: "b", Payload: "p2", Severity: "HIGH"},
	}
	curr := []Finding{
		{Type: "XSS", URL: "http://x/?a=1", Method: "GET", Parameter: "a", Payload: "p1", Severity: "MEDIUM"},
		{Type: "IDOR", URL: "http://x/?c=3", Method: "GET", Parameter: "c", Payload: "p3", Severity: "HIGH"},
	}
	d := Compare(prev, curr)
	if len(d.Added) != 1 || d.Added[0].Type != "IDOR" {
		t.Errorf("added = %+v", d.Added)
	}
	if len(d.Fixed) != 1 || d.Fixed[0].Type != "SQL Injection" {
		t.Errorf("fixed = %+v", d.Fixed)
	}
	if len(d.Changed) != 1 || d.Changed[0].Type != "XSS" {
		t.Errorf("changed = %+v", d.Changed)
	}
	if d.Same != 0 {
		t.Errorf("same = %d", d.Same)
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	fs := []Finding{
		{Type: "XSS", URL: "http://x/", Method: "GET", Parameter: "a", Payload: "x", Severity: "LOW"},
		{Type: "XSS", URL: "http://x/", Method: "GET", Parameter: "a", Payload: "x", Severity: "LOW"},
	}
	if err := SaveState(path, fs); err != nil {
		t.Fatal(err)
	}
	s, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Findings) != 1 {
		t.Errorf("state findings = %d (dedupe should collapse), got %+v", len(s.Findings), s.Findings)
	}
	if s.Generated == "" {
		t.Error("generated timestamp missing")
	}
	if _, err := LoadState(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected error for missing state")
	}
}

func TestSendWebhook(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	fs := []Finding{{Type: "SQL Injection", URL: "http://x/?id=1", Method: "GET", Parameter: "id", Payload: "'", Severity: "CRITICAL", Evidence: "e"}}
	if err := SendWebhook(srv.URL, "slack", "", "sxel scan", fs, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["text"]; !ok {
		t.Errorf("slack payload = %v", got)
	}
	if err := SendWebhook(srv.URL, "discord", "", "sxel scan", fs, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["content"]; !ok {
		t.Errorf("discord payload = %v", got)
	}
	if err := SendWebhook(srv.URL, "telegram", "12345", "sxel scan", fs, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if got["chat_id"] != "12345" || got["text"] == "" {
		t.Errorf("telegram payload = %v", got)
	}
}

func TestSendWebhookError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	err := SendWebhook(srv.URL, "slack", "", "t", []Finding{{Type: "X", URL: "u", Method: "GET", Severity: "LOW"}}, 5*time.Second)
	if err == nil {
		t.Error("expected error on 500")
	}
}

func TestFromScanResults(t *testing.T) {
	rs := []core.ScanResult{{
		Type: "SQL Injection", URL: "http://x/", Method: "GET",
		Parameter: "id", Payload: "'", Severity: "HIGH", Evidence: "e",
		Timestamp: time.Now(),
	}}
	fs := FromScanResults(rs)
	if len(fs) != 1 || fs[0].Type != "SQL Injection" || fs[0].Timestamp == "" {
		t.Errorf("FromScanResults = %+v", fs)
	}
}
