package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestChecksumFromContentPlainHash(t *testing.T) {
	content := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
	if got := checksumFromContent(content, "sxel-linux-amd64", true); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("plain hash line not recognized: %q", got)
	}
}

func TestChecksumFromContentNamedLine(t *testing.T) {
	h := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	content := h + "  sxel-linux-amd64\n" + "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  other-file\n"
	if got := checksumFromContent(content, "sxel-linux-amd64", false); got != h {
		t.Fatalf("named line not matched: %q", got)
	}
}

func TestChecksumFromContentOtherNameIgnored(t *testing.T) {
	content := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  other-file\n"
	if got := checksumFromContent(content, "sxel-linux-amd64", false); got != "" {
		t.Fatalf("unrelated line matched: %q", got)
	}
	if got := checksumFromContent(content, "sxel-linux-amd64", true); got != "" {
		t.Fatalf("unrelated line matched in single-column mode: %q", got)
	}
}

func TestVerifyBinaryMatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	data := []byte("sxel-test-binary")
	if err := os.WriteFile(p, data, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if err := verifyBinary(p, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("matching checksum rejected: %v", err)
	}
	if err := verifyBinary(p, hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("mismatched checksum accepted")
	}
}
