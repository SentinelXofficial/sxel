package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestTemplateVarsStore(t *testing.T) {
	var sameMoveToken, nextMoveToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Write([]byte(`<input name="csrf" value="abc123">`))
		case "/check":
			sameMoveToken = r.URL.Query().Get("token")
			w.Write([]byte("ok"))
		case "/submit":
			nextMoveToken = r.URL.Query().Get("token")
			w.Write([]byte("done"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tmpl := Template{
		ID: "vars-store-test",
		Moves: []TemplateMove{
			{
				Verb: "GET",
				To: []string{
					"{{BaseURL}}/login",
					"{{BaseURL}}/check?token={{vars:token}}",
				},
				Capture: []string{
					`token=name="csrf" value="([^"]+)"`,
				},
			},
			{
				Verb:  "GET",
				To:    []string{"{{BaseURL}}/submit?token={{vars:token}}"},
				Signs: []TemplateSign{{On: "word", Has: []string{"done"}}},
			},
		},
	}

	results := RunTemplates(http.DefaultClient, &core.Config{}, server.URL, []Template{tmpl})
	if sameMoveToken != "abc123" {
		t.Errorf("same-move request token = %q, want %q", sameMoveToken, "abc123")
	}
	if nextMoveToken != "abc123" {
		t.Errorf("next-move request token = %q, want %q", nextMoveToken, "abc123")
	}
	if len(results) != 1 {
		t.Errorf("got %d scan results, want 1 (only the /submit move matches)", len(results))
	}
}

func TestTemplateVarsStoreUnsetPassthrough(t *testing.T) {
	var gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/submit" {
			http.NotFound(w, r)
			return
		}
		gotToken = r.URL.Query().Get("token")
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	tmpl := Template{
		ID: "vars-unset-test",
		Moves: []TemplateMove{
			{
				Verb:  "GET",
				To:    []string{"{{BaseURL}}/submit?token={{vars:missing}}"},
				Signs: []TemplateSign{{On: "word", Has: []string{"ok"}}},
			},
		},
	}

	results := RunTemplates(http.DefaultClient, &core.Config{}, server.URL, []Template{tmpl})
	if gotToken != "{{vars:missing}}" {
		t.Errorf("request token = %q, want literal %q", gotToken, "{{vars:missing}}")
	}
	if len(results) != 1 {
		t.Errorf("got %d scan results, want 1", len(results))
	}
}
