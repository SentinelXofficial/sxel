package modules

import "testing"

func TestNormalizeRaceBodyDigits(t *testing.T) {
	a := `{"id": 12345, "created": 1712345678}`
	b := `{"id": 67890, "created": 1712345679}`
	if normalizeRaceBody(a) != normalizeRaceBody(b) {
		t.Fatal("bodies differing only in digits should normalize equal")
	}
	other := `{"id": 12345, "owner": "bob"}`
	if normalizeRaceBody(a) == normalizeRaceBody(other) {
		t.Fatal("bodies differing in content should stay distinct")
	}
}

func TestIdorTokenDiff(t *testing.T) {
	if idorTokenDiff("hello world", "hello world") != 0 {
		t.Fatal("identical bodies should have 0 token diff")
	}
	if idorTokenDiff("user alice admin", "user bob admin") < 2 {
		t.Fatal("different record tokens should register")
	}
	if idorTokenDiff("", "x") != 1 {
		t.Fatal("single new token should count 1")
	}
}
