package modules

import (
	"strings"
	"testing"
)

func TestSSRFProbeVariantsPresent(t *testing.T) {
	payloads := []string{}
	labels := map[string]bool{}
	for _, p := range ssrfProbes {
		payloads = append(payloads, p.Payload)
		labels[p.Label] = true
	}
	for _, want := range []string{"2130706433", "0x7f000001", "127.1", "[::1]", "017700000001", "100.100.100.200"} {
		found := false
		for _, p := range payloads {
			if strings.Contains(p, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("probe with %q missing", want)
		}
	}
	if !labels["Aliyun Metadata"] {
		t.Fatal("aliyun metadata probe missing")
	}
}
