package poc

import (
	"net/http"
	"testing"
	"time"
)

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

func TestNilRuleReturnsErrorNotPanic(t *testing.T) {
	p := &PoC{
		Name:       "nil-rule",
		Transport:  "http",
		Expression: "true",
		Rules:      map[string]*Rule{"r0": nil},
	}
	for _, e := range p.Lint() {
		if e == `rule "r0": empty request` {
			return
		}
	}
	t.Fatalf("Lint should flag the nil rule, got %v", p.Lint())

	p2 := &PoC{
		Name:       "nil-rule-run",
		Transport:  "http",
		Expression: "true",
		Rules:      map[string]*Rule{"r0": nil},
	}
	client := &http.Client{Timeout: 2 * time.Second}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Run panicked on nil rule: %v", r)
		}
	}()
	_, _, err := p2.Run(client, "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("Run should return an error for a nil rule")
	}
}
