package engine

import (
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestSameSiteOrSubdomain(t *testing.T) {
	cases := []struct {
		host, base string
		want       bool
	}{
		{"example.test", "example.test", true},
		{"example.test:80", "example.test", true},
		{"hallo.example.test", "example.test", true},
		{"hallo.example.test:443", "example.test", true},
		{"hallo.example.test:8901", "site.localhost:8900", false},
		{"sub.site.localhost:8901", "site.localhost:8900", true},
		{"a.b.example.test", "example.test", true},
		{"example.test.evil.test", "example.test", false},
		{"hallo.me.test", "example.test", false},
		{"www.other.test", "example.test", false},
		{"evil.example.test.attacker.test", "example.test", false},
		{"[::1]:8080", "[::1]", true},
		{"[2001:db8::1]", "[2001:db8::2]", false},
	}
	for _, c := range cases {
		if got := SameSiteOrSubdomain(c.host, c.base); got != c.want {
			t.Errorf("SameSiteOrSubdomain(%q, %q) = %v, want %v", c.host, c.base, got, c.want)
		}
	}
}

func TestIsInScopeSubdomainRule(t *testing.T) {
	c := NewCrawler(nil, &core.Config{})
	c.baseHost = "example.test"

	in := []string{
		"http://example.test/x",
		"http://hallo.example.test/y",
		"https://a.b.example.test/z",
	}
	for _, u := range in {
		if !c.IsInScope(u) {
			t.Errorf("expected %q in scope (site or subdomain)", u)
		}
	}
	out := []string{
		"http://hallo.me.test/y",
		"http://other.test/x",
		"http://example.test.evil.test/x",
	}
	for _, u := range out {
		if c.IsInScope(u) {
			t.Errorf("expected %q out of scope (foreign domain)", u)
		}
	}
}
