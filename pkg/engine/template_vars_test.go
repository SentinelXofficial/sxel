package engine

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	tvBaseURL   = "http://example.com"
	tvHostname  = "example.com"
	tvOOBURL    = "oob.example.net"
	tvOOBDomain = "attacker.example.com"
)

func TestTemplateVarsExact(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"baseurl still expands", "{{BaseURL}}", tvBaseURL},
		{"hostname", "{{Hostname}}", tvHostname},
		{"interactsh-url", "{{interactsh-url}}", tvOOBURL},
		{"oob-url", "{{OOB_URL}}", tvOOBURL},
		{"base64", "{{base64:hello}}", base64.StdEncoding.EncodeToString([]byte("hello"))},
		{"base64 nested baseurl", "{{base64:{{BaseURL}}}}", base64.StdEncoding.EncodeToString([]byte(tvBaseURL))},
		{"str-replace", "{{str-replace:foo|bar|foo foo foo}}", "bar bar bar"},
		{"str-replace nested", "{{str-replace:{{Hostname}}|X|{{Hostname}}-{{Hostname}}}}", "X-X"},
		{"str-replace two parts", "{{str-replace:foo|bar}}", "{{str-replace:foo|bar}}"},
		{"str-replace one part", "{{str-replace:foo}}", "{{str-replace:foo}}"},
		{"str-replace no args", "{{str-replace:}}", "{{str-replace:}}"},
		{"compare equal", "{{compare:a|a}}", "1"},
		{"compare unequal", "{{compare:a|b}}", "0"},
		{"compare single non-empty", "{{compare:hello}}", "1"},
		{"compare single empty", "{{compare:}}", "0"},
		{"compare nested", "{{compare:{{BaseURL}}|http://example.com}}", "1"},
		{"x-www-form-urlencoded", "{{x-www-form-urlencoded:a b&c=d}}", "a+b%26c%3Dd"},
		{"json escape", `{{json:a"b}}`, `a\"b`},
		{"vars passthrough", "{{vars:user-id}}", "{{vars:user-id}}"},
		{"vars with colon", "{{vars:token:admin}}", "{{vars:token:admin}}"},
		{"unknown token passthrough", "{{no-such-token:abc}}", "{{no-such-token:abc}}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandTemplateVars(tt.in, tvBaseURL, tvHostname, tvOOBURL, "")
			if got != tt.want {
				t.Errorf("ExpandTemplateVars(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTemplateVarsDnslog(t *testing.T) {
	withDomainRe := regexp.MustCompile(`^[0-9a-f]{8}\.attacker\.example\.com$`)
	for i := 0; i < 20; i++ {
		got := ExpandTemplateVars("{{dnslog}}", tvBaseURL, tvHostname, tvOOBURL, tvOOBDomain)
		if !withDomainRe.MatchString(got) {
			t.Fatalf("dnslog with domain = %q, want %s", got, withDomainRe)
		}
	}

	for i := 0; i < 20; i++ {
		got := ExpandTemplateVars("{{dnslog}}", tvBaseURL, tvHostname, tvOOBURL, "")
		if !strings.HasSuffix(got, ".dnslog") {
			t.Fatalf("dnslog without domain = %q, want suffix .dnslog", got)
		}
	}
}

func TestTemplateDnslogName(t *testing.T) {
	withDomainRe := regexp.MustCompile(`^[0-9a-f]{8}\.attacker\.example\.com$`)
	plainRe := regexp.MustCompile(`^[0-9a-f]{8}\.dnslog$`)
	for i := 0; i < 20; i++ {
		if got := TemplateDnslogName(tvOOBDomain); !withDomainRe.MatchString(got) {
			t.Fatalf("TemplateDnslogName(%q) = %q, want %s", tvOOBDomain, got, withDomainRe)
		}
		if got := TemplateDnslogName(""); !plainRe.MatchString(got) {
			t.Fatalf("TemplateDnslogName(\"\") = %q, want %s", got, plainRe)
		}
	}
}

func TestTemplateVarsRandom(t *testing.T) {
	pathRe := regexp.MustCompile(`^\d{6}$`)
	jsonpRe := regexp.MustCompile(`^sxelCallback[0-9a-f]{4}$`)
	dnslogRe := regexp.MustCompile(`^[0-9a-f]{8}\.dnslog$`)

	for i := 0; i < 50; i++ {
		got := ExpandTemplateVars("{{path-int}}", tvBaseURL, tvHostname, tvOOBURL, "")
		if !pathRe.MatchString(got) {
			t.Fatalf("path-int = %q, want 6-digit number", got)
		}
		n, err := strconv.Atoi(got)
		if err != nil || n < 100000 || n > 999999 {
			t.Fatalf("path-int = %q, want value in [100000, 999999]", got)
		}
	}

	prevJSONP := ""
	for i := 0; i < 20; i++ {
		got := ExpandTemplateVars("{{jsonp}}", tvBaseURL, tvHostname, tvOOBURL, "")
		if !jsonpRe.MatchString(got) {
			t.Fatalf("jsonp = %q, want %s", got, jsonpRe)
		}
		if i > 0 && got == prevJSONP {
			t.Fatalf("jsonp repeated: %q", got)
		}
		prevJSONP = got
	}

	prevDNS := ""
	for i := 0; i < 20; i++ {
		got := ExpandTemplateVars("{{dnslog}}", tvBaseURL, tvHostname, tvOOBURL, "")
		if !dnslogRe.MatchString(got) {
			t.Fatalf("dnslog = %q, want %s", got, dnslogRe)
		}
		if i > 0 && got == prevDNS {
			t.Fatalf("dnslog repeated: %q", got)
		}
		prevDNS = got
	}
}
