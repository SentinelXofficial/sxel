package engine

import (
	"testing"
	"time"
)

func TestHasInteractionRobust(t *testing.T) {
	d := &DNSOOB{queries: []DNSInteraction{{QName: "sxel-abc.example.com."}}}
	if !d.HasInteraction("sxel-abc.example.com") {
		t.Fatal("exact match with trailing dot should hit")
	}
	if !d.HasInteraction("SXEL-ABC.example.com.") {
		t.Fatal("case-insensitive match should hit")
	}
	if d.HasInteraction("sxel-xyz.example.com") {
		t.Fatal("unrelated qname must not match")
	}
	if d.HasInteraction("example.com") {
		t.Fatal("prefix of qname must not match")
	}
}

func TestHasInteractionNil(t *testing.T) {
	var d *DNSOOB
	if d.HasInteraction("anything") {
		t.Fatal("nil dns must not report interaction")
	}
}

func TestWaitForDNSImmediate(t *testing.T) {
	d := &DNSOOB{queries: []DNSInteraction{{QName: "sxel-1.oob"}}}
	if !waitForDNS(d, "sxel-1.oob", 100*time.Millisecond) {
		t.Fatal("seeded interaction should be detected")
	}
}
