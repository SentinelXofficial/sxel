package engine

import (
	"net/http"
	"testing"
)

func TestMatchSignsMixedNeedIsOR(t *testing.T) {
	signs := []TemplateSign{
		{On: "word", Has: []string{"alpha"}, Need: "all"},
		{On: "word", Has: []string{"beta"}},
	}
	if !matchSigns(signs, "only beta here", nil) {
		t.Fatal("independent signs should be OR — sign 2 matched but result was false")
	}
}

func TestMatchSignsAllNeedAllIsAND(t *testing.T) {
	signs := []TemplateSign{
		{On: "word", Has: []string{"alpha"}, Need: "all"},
		{On: "word", Has: []string{"beta"}, Need: "all"},
	}
	if matchSigns(signs, "only beta here", nil) {
		t.Fatal("when every sign needs all, group must be AND — only one sign matched")
	}
	if !matchSigns(signs, "alpha and beta here", nil) {
		t.Fatal("when every sign needs all, both matching should succeed")
	}
}

func TestMatchSignsStatusWithoutOnField(t *testing.T) {
	signs := []TemplateSign{{Status: []int{200}}}
	resp := &http.Response{StatusCode: 200}
	if !matchSigns(signs, "", resp) {
		t.Fatal("status-only sign without explicit on:status should classify as status sign")
	}
}

func TestMatchSignsStatusGroupOR(t *testing.T) {
	signs := []TemplateSign{
		{On: "status", Status: []int{403}},
		{On: "status", Status: []int{200}},
	}
	if !matchSigns(nil, "", &http.Response{StatusCode: 403}) && len(signs) == 0 {
		t.Fatal("unreachable")
	}
	if !evalStatusGroup(signs, &http.Response{StatusCode: 403}) {
		t.Fatal("one of two independent status signs matching should pass (OR)")
	}
	if evalStatusGroup(signs, &http.Response{StatusCode: 500}) {
		t.Fatal("no status sign matched, should fail")
	}
}
