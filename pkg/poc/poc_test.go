package poc

import "testing"

func TestEvalComparisons(t *testing.T) {
	cases := map[string]bool{
		"response.status == 200":                           true,
		"response.status != 200":                           false,
		"response.status >= 200 && response.status < 300":  true,
		"response.body.bcontains(\"hello\")":               true,
		"!response.body.bcontains(\"nope\")":               true,
		"response.body.matches(\"h[ae]llo\")":              true,
		"response.headers[\"Server\"].contains(\"nginx\")": true,
		"response.content_type.contains(\"json\")":         false,
	}
	for expr, want := range cases {
		c := evalCtx{resp: &Response{
			Status:      200,
			Body:        "<html>hello world</html>",
			ContentType: "text/html",
			Headers:     map[string][]string{"Server": {"nginx"}},
		}}
		got, err := evalBool(expr, c)
		if err != nil {
			t.Errorf("%q error: %v", expr, err)
			continue
		}
		if got != want {
			t.Errorf("%q = %v, want %v", expr, got, want)
		}
	}
}

func TestEvalSetFunctions(t *testing.T) {
	c := evalCtx{set: map[string]string{}}
	v, err := evalValue("randomInt(5, 8)", c)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := toNum(v)
	if n < 5 || n >= 8 {
		t.Errorf("randomInt out of range: %v", v)
	}
	v, err = evalValue("tolower(\"ABC\")", c)
	if err != nil {
		t.Fatal(err)
	}
	if toStr(v) != "abc" {
		t.Errorf("tolower = %q", toStr(v))
	}
}

func TestEvalRuleChain(t *testing.T) {
	c := evalCtx{
		set:   map[string]string{"r0": "abc"},
		rules: map[string]bool{"r0": true},
		resp:  &Response{Status: 200, Body: "ok"},
	}
	got, err := evalBool("r0() && response.status == 200", c)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("r0() && status==200 should be true")
	}
}
