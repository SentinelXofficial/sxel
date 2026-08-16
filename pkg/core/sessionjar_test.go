package core

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestSessionJarLearnAndReplay(t *testing.T) {
	var seenSession string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenSession = r.Header.Get("Cookie")
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess123"})
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &Config{Session: NewSessionJar("")}
	client := NewHTTPClient(cfg)

	if _, _, err := DoGET(client, cfg, srv.URL+"/login"); err != nil {
		t.Fatal(err)
	}
	if seenSession != "" {
		t.Fatalf("unexpected cookie before learn: %q", seenSession)
	}
	if _, _, err := DoGET(client, cfg, srv.URL+"/profile"); err != nil {
		t.Fatal(err)
	}
	if seenSession != "session=sess123" {
		t.Fatalf("learned cookie not replayed: %q", seenSession)
	}
}

func TestSessionJarHostScope(t *testing.T) {
	j := NewSessionJar("")
	u, _ := url.Parse("http://app.example.com/")
	j.SetCookies(u, []*http.Cookie{{Name: "sid", Value: "x"}})
	sub, _ := url.Parse("http://deep.app.example.com/")
	if len(j.Cookies(sub)) != 0 {
		t.Fatalf("host-only cookie must not leak to subdomain: %+v", j.Cookies(sub))
	}
	same, _ := url.Parse("http://app.example.com/p")
	if len(j.Cookies(same)) != 1 {
		t.Fatalf("host-only cookie must apply to exact host: %+v", j.Cookies(same))
	}
	other, _ := url.Parse("http://evil.com/")
	if len(j.Cookies(other)) != 0 {
		t.Fatal("cookie must not leak to unrelated host")
	}
}

func TestSessionJarDomainScope(t *testing.T) {
	j := NewSessionJar("")
	u, _ := url.Parse("http://www.example.com/")
	j.SetCookies(u, []*http.Cookie{{Name: "sid", Value: "x", Domain: ".example.com", Path: "/app"}})
	sub, _ := url.Parse("http://api.example.com/app")
	if len(j.Cookies(sub)) != 1 {
		t.Fatalf("domain-scoped cookie must reach sibling subdomain: %+v", j.Cookies(sub))
	}
	nested, _ := url.Parse("http://deep.api.example.com/app/")
	if len(j.Cookies(nested)) != 1 {
		t.Fatalf("domain-scoped cookie must reach nested subdomain path: %+v", j.Cookies(nested))
	}
	noPath, _ := url.Parse("http://api.example.com/other")
	if len(j.Cookies(noPath)) != 0 {
		t.Fatalf("domain cookie with Path=/app must not match /other: %+v", j.Cookies(noPath))
	}
}

func TestSessionJarExpiry(t *testing.T) {
	j := NewSessionJar("")
	u, _ := url.Parse("http://h.test/")
	j.SetCookies(u, []*http.Cookie{{Name: "dead", Value: "x", Expires: time.Now().Add(-time.Hour)}})
	j.SetCookies(u, []*http.Cookie{{Name: "neg", Value: "x", MaxAge: -1}})
	if len(j.Cookies(u)) != 0 {
		t.Fatalf("expired cookies still returned: %+v", j.Cookies(u))
	}
}

func TestSessionJarDelete(t *testing.T) {
	j := NewSessionJar("")
	u, _ := url.Parse("http://h.test/")
	j.SetCookies(u, []*http.Cookie{{Name: "sid", Value: "x"}})
	j.SetCookies(u, []*http.Cookie{{Name: "sid", Value: ""}})
	if len(j.Cookies(u)) != 0 {
		t.Fatal("deleted cookie still returned")
	}
}

func TestSessionJarSeedCookies(t *testing.T) {
	j := NewSessionJar("auth=abc123; theme=dark")
	u, _ := url.Parse("http://h.test/")
	if len(j.Cookies(u)) != 0 {
		t.Fatalf("seed must not be stored in jar (applied via Cookie header): %+v", j.Cookies(u))
	}
}
