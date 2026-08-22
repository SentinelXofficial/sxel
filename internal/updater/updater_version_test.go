package updater

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.10", "1.3.0", -1},
		{"1.3.0", "1.2.10", 1},
		{"2.0", "1.9.9", 1},
		{"1.10.0", "1.9.0", 1},
		{"1.2", "1.2.0", 0},
		{"1.2.0", "1.2.1", -1},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0", "1.0.0-beta", 1},
		{"2024.01.15", "2024.1.15", 0},
		{"1.23", "1.3", 1},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSplitVersion(t *testing.T) {
	segs, suffix := splitVersion("v1.2.3-beta")
	if len(segs) != 3 || segs[0] != 1 || segs[1] != 2 || segs[2] != 3 {
		t.Fatalf("splitVersion segments = %v, want [1 2 3]", segs)
	}
	if suffix != "-beta" {
		t.Fatalf("suffix = %q, want %q", suffix, "-beta")
	}
}
