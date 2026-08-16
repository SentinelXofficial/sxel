package integration

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
)

// ---------- SQLi ----------

func sqliVulnHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if strings.Contains(id, "'") || strings.Contains(id, "\"") {
		fmt.Fprintf(w, "MySQL error: You have an error in your SQL syntax near '%s' at line 1", id)
		return
	}
	fmt.Fprintf(w, "<html><body><h1>User %s</h1><p>profile</p></body></html>", html.EscapeString(id))
}

func sqliSafeHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if strings.Contains(id, "'") || strings.Contains(id, "\"") {
		http.Error(w, "invalid input", 400)
		return
	}
	fmt.Fprintf(w, "<html><body><h1>User %s</h1><p>profile</p></body></html>", html.EscapeString(id))
}

// ---------- XSS ----------

func xssVulnTextHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, "<html><head><title>Search</title></head><body><div>Results for: %s</div></body></html>", q)
}

func xssVulnScriptHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, "<html><body><script>var q = \"%s\"</script><p>ok</p></body></html>", q)
}

func xssVulnAttrHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, `<html><body><a href="%s">link</a></body></html>`, q)
}

func xssSafeHandler(w http.ResponseWriter, r *http.Request) {
	q := html.EscapeString(r.URL.Query().Get("q"))
	fmt.Fprintf(w, "<html><head><title>Search</title></head><body><div>Results for: %s</div></body></html>", q)
}

// ---------- SSRF ----------

func ssrfVulnHandler(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("url")
	if strings.Contains(u, "169.254.169.254") {
		fmt.Fprint(w, "ami-id: ami-0c02fb55956cbb732\ninstance-id: i-0ab1234\n")
		return
	}
	fmt.Fprintf(w, "fetch result for %s: ok\n", html.EscapeString(u))
}

func ssrfSafeHandler(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("url")
	fmt.Fprintf(w, "request ignored, target not fetched: %s\n", html.EscapeString(u))
}

// ---------- JWT ----------

func jwtAuthHandler(secret string, insecure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := ""
		if ah := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(ah), "bearer ") {
			tok = strings.TrimSpace(ah[len("Bearer "):])
		}
		if tok == "" {
			for _, part := range strings.Split(r.Header.Get("Cookie"), ";") {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) == 2 && kv[0] == "session" {
					tok = kv[1]
				}
			}
		}
		if tok == "" {
			w.WriteHeader(401)
			fmt.Fprint(w, "unauthorized")
			return
		}
		if insecure && jwtAcceptsInsecure(tok) {
			fmt.Fprint(w, "authorized: top-secret data")
			return
		}
		if jwtVerifyHS256(tok, secret) {
			fmt.Fprint(w, "authorized: top-secret data")
			return
		}
		w.WriteHeader(401)
		fmt.Fprint(w, "unauthorized")
	})
}

func jwtAcceptsInsecure(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	alg := jwtHeaderField(parts[0], "alg")
	if strings.EqualFold(alg, "none") {
		return true
	}
	if parts[2] == "" {
		return true
	}
	return false
}

// ---------- GraphQL ----------

func gqlWrite(w http.ResponseWriter, payload string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, payload)
}

func gqlReadQuery(r *http.Request) string {
	var body struct {
		Query string `json:"query"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	return strings.TrimSpace(body.Query)
}

func gqlVulnHandler(w http.ResponseWriter, r *http.Request) {
	q := gqlReadQuery(r)
	switch {
	case strings.HasPrefix(q, "["):
		gqlWrite(w, `[{"data":{"__typename":"Query"}}]`)
	case strings.Contains(q, "__schema"):
		gqlWrite(w, `{"data":{"__schema":{"types":[{"name":"Query","fields":[{"name":"user","type":{"name":"String","ofType":{"name":"String","ofType":null}}}]}]}}}`)
	case strings.Contains(q, "alias"):
		gqlWrite(w, `{"data":{"alias0":"Query","alias1":"Query"}}`)
	case strings.Contains(q, "__typename"):
		gqlWrite(w, `{"data":{"__typename":"Query"}}`)
	default:
		gqlWrite(w, `{"data":{}}`)
	}
}

func gqlSafeHandler(w http.ResponseWriter, r *http.Request) {
	q := gqlReadQuery(r)
	switch {
	case strings.HasPrefix(q, "["):
		gqlWrite(w, `{"errors":[{"message":"Batching not supported"}]}`)
	case strings.Contains(q, "__schema"):
		gqlWrite(w, `{"errors":[{"message":"Cannot query field '__schema' on type 'Query'"}]}`)
	case strings.Count(q, "alias") > 10:
		gqlWrite(w, `{"errors":[{"message":"Too many aliases"}]}`)
	case strings.Contains(q, "__typename"):
		gqlWrite(w, `{"data":{"__typename":"Query"}}`)
	default:
		gqlWrite(w, `{"errors":[{"message":"Unknown query"}]}`)
	}
}

// ---------- CMDi (blind timing) ----------

func cmdiVulnHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if cmd == "" || strings.Contains(cmd, "sleep") || strings.Contains(cmd, "ping") {
		time.Sleep(3200 * time.Millisecond)
	}
	fmt.Fprint(w, "command executed: done")
}

func cmdiSafeHandler(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("cmd")
	fmt.Fprint(w, "command executed: done")
}

// ---------- NoSQLi ----------

func nosqlVulnHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, vs := range q {
		v := ""
		if len(vs) > 0 {
			v = vs[0]
		}
		trueCond := strings.Contains(k, "[$ne]") || strings.Contains(k, "[$gt]") ||
			strings.Contains(k, "[$in]") || (strings.Contains(k, "[$regex]") && v == ".*") ||
			(strings.Contains(k, "[$exists]") && v == "true")
		if trueCond {
			fmt.Fprint(w, strings.Repeat("A", 900))
			return
		}
	}
	fmt.Fprint(w, "false")
}

func nosqlSafeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, strings.Repeat("B", 400))
}
