package modules

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSoleHostnameToken(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"xml wrapped", `<root><data>web-01.local</data></root>`, "web-01.local"},
		{"plain body", "ip-10-0-0-5\n", "ip-10-0-0-5"},
		{"cdata wrapped", "<resp><![CDATA[host123]]></resp>", "host123"},
		{"error xml must not match", `<error><message>bad doctype</message></error>`, ""},
		{"verbose error must not match", `<response><status>failed</status><detail>could not load entity</detail></response>`, ""},
		{"multi-word text must not match", `<data>hello world</data>`, ""},
		{"empty response", "", ""},
	}
	for _, c := range cases {
		if got := soleHostnameToken(c.body); got != c.want {
			t.Errorf("%s: soleHostnameToken(%q) = %q, want %q", c.name, c.body, got, c.want)
		}
	}
}

func TestBase64HostnameToken(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("myhost"))
	body := `<resp>` + enc + `</resp>`
	if got := base64HostnameToken(body); got != "myhost" {
		t.Errorf("base64HostnameToken = %q, want %q", got, "myhost")
	}
	if got := base64HostnameToken(`<err>` + base64.StdEncoding.EncodeToString([]byte("not a hostname value here")) + `</err>`); got != "" {
		t.Errorf("base64HostnameToken should reject non-hostname content, got %q", got)
	}
}

func TestXXEHostnameNoFalsePositiveOnXMLError(t *testing.T) {
	baseline := `<?xml version="1.0"?><root><data>test</data></root>`
	payloadResp := `<error><message>Invalid DOCTYPE declaration</message></error>`
	tok := soleHostnameToken(payloadResp)
	if tok == "" && !strings.Contains(baseline, tok) {
		return
	}
	if tok != "" && !strings.Contains(strings.ToLower(baseline), strings.ToLower(tok)) {
		t.Fatalf("false positive: error page yielded CRITICAL XXE finding with token %q", tok)
	}
}
