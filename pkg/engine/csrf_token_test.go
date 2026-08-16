package engine

import (
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestExtractFormsCSRFHiddenInput(t *testing.T) {
	body := `<html><body>
<form method="POST" action="/submit">
<input type="hidden" name="_token" value="abc123token">
<input type="text" name="username">
<input type="submit" value="Go">
</form>
</body></html>`
	forms := ExtractForms(body, "http://127.0.0.1:1/")
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	f := forms[0]
	if f.TokenName != "_token" || f.TokenValue != "abc123token" {
		t.Fatalf("token not captured: %q=%q", f.TokenName, f.TokenValue)
	}
	for _, inp := range f.Inputs {
		if inp.Name == "_token" {
			t.Fatal("token input should not remain in fuzzable Inputs")
		}
	}
	if len(f.Inputs) != 1 || f.Inputs[0].Name != "username" {
		t.Fatalf("unexpected inputs: %+v", f.Inputs)
	}
}

func TestExtractFormsMetaCSRFToken(t *testing.T) {
	body := `<html><head>
<meta name="csrf-token" content="metatoken99">
</head><body>
<form method="POST" action="/a"><input type="text" name="q"></form>
<form method="POST" action="/b"><input type="text" name="r"></form>
</body></html>`
	forms := ExtractForms(body, "http://127.0.0.1:1/")
	if len(forms) != 2 {
		t.Fatalf("expected 2 forms, got %d", len(forms))
	}
	for _, f := range forms {
		if f.TokenName != "_token" || f.TokenValue != "metatoken99" {
			t.Fatalf("meta token not propagated: %+v", f)
		}
	}
}

func TestFormDefaultsIncludesToken(t *testing.T) {
	f := core.Form{
		Action:     "http://127.0.0.1:1/submit",
		Method:     "POST",
		TokenName:  "_token",
		TokenValue: "tok123",
		Inputs:     []core.Input{{Name: "username", Type: "text"}},
	}
	v := core.FormDefaults(f)
	if v.Get("_token") != "tok123" {
		t.Fatalf("token missing from FormDefaults: %v", v)
	}
	if v.Get("username") == "" {
		t.Fatalf("regular input missing: %v", v)
	}
	enc := v.Encode()
	if !strings.Contains(enc, "_token=tok123") {
		t.Fatalf("encoded body missing token: %s", enc)
	}
}
