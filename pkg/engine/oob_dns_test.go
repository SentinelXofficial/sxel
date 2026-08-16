package engine

import (
	"net"
	"testing"
)

func dnsQueryPacket(qname string) []byte {
	pkt := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range splitLabels(qname) {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, label...)
	}
	pkt = append(pkt, 0x00, 0x00, 0x01, 0x00, 0x01)
	return pkt
}

func splitLabels(qname string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(qname); i++ {
		if i == len(qname) || qname[i] == '.' {
			if i > start {
				out = append(out, qname[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestParseDNSQuery(t *testing.T) {
	qname, qtype, ok := parseDNSQuery(dnsQueryPacket("deadbeef.attacker.example.com"))
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if qname != "deadbeef.attacker.example.com" {
		t.Fatalf("qname = %q", qname)
	}
	if qtype != "A" {
		t.Fatalf("qtype = %q", qtype)
	}

	resp := dnsQueryPacket("x.y")
	resp[2] |= 0x80
	if _, _, ok := parseDNSQuery(resp); ok {
		t.Fatal("response packet must not be parsed as query")
	}
}

func TestBuildDNSReply(t *testing.T) {
	q := dnsQueryPacket("a.b.example.com")
	rep := buildDNSReply(q, "a.b.example.com", "A", net.IPv4(10, 0, 0, 1))
	if rep == nil {
		t.Fatal("nil reply")
	}
	if len(rep) < 12 {
		t.Fatal("reply too short")
	}
	if rep[2]&0x80 == 0 {
		t.Fatal("QR bit not set in reply")
	}
	if rep[0] != 0x12 || rep[1] != 0x34 {
		t.Fatal("ID not echoed")
	}
	if rep[6] != 0 || rep[7] != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", int(rep[7]))
	}
	found := false
	for _, b := range rep {
		if b == 10 {
			found = true
		}
	}
	if !found {
		t.Fatal("reply does not contain A record for self IP")
	}
	rep2 := buildDNSReply(q, "a.b.example.com", "TXT", net.IPv4(10, 0, 0, 1))
	if rep2 == nil || rep2[7] != 0 {
		t.Fatal("TXT reply should have zero answers")
	}
}
