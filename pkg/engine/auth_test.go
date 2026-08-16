package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func TestAuthenticateSuccess(t *testing.T) {
	var sessionCookie *http.Cookie
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/login" {
			if err := r.ParseForm(); err == nil {
				if r.Form.Get("username") == "admin" && r.Form.Get("password") == "s3cret" {
					sessionCookie = &http.Cookie{Name: "session", Value: "valid-session-token", Path: "/"}
					http.SetCookie(w, sessionCookie)
					w.WriteHeader(302)
					w.Header().Set("Location", "/dashboard")
					return
				}
			}
			w.WriteHeader(401)
			w.Write([]byte("invalid credentials"))
			return
		}
		if r.URL.Path == "/dashboard" {
			w.Write([]byte("<html><h1>Dashboard admin</h1></html>"))
			return
		}
		w.Write([]byte(`<html><form method="POST" action="/login"><input name="username"><input name="password" type="password"><button>Login</button></form></html>`))
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test"}
	client := core.NewHTTPClient(cfg)
	ok, err := Authenticate(client, cfg, AuthConfig{
		LoginURL:  srv.URL + "/login",
		Username:  "admin",
		Password:  "s3cret",
		VerifyURL: srv.URL + "/dashboard",
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if !ok {
		t.Fatal("expected successful authentication")
	}
	body, status, err := core.DoGET(client, cfg, srv.URL+"/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 || !strings.Contains(body, "Dashboard admin") {
		t.Errorf("authenticated GET failed: status=%d body=%q", status, body)
	}
	if sessionCookie == nil {
		t.Error("login endpoint never received credentials")
	}
}

func TestAuthenticateBadCreds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/login" {
			w.WriteHeader(401)
			w.Write([]byte("bad creds"))
			return
		}
		w.Write([]byte(`<html><form method="POST" action="/login"><input name="username"><input name="password" type="password"></form></html>`))
	}))
	defer srv.Close()

	cfg := &core.Config{UserAgent: "sxel-test"}
	client := core.NewHTTPClient(cfg)
	_, err := Authenticate(client, cfg, AuthConfig{
		LoginURL: srv.URL + "/login",
		Username: "admin",
		Password: "wrong",
	})
	if err == nil {
		t.Error("expected error on rejected credentials")
	}
}

func TestAuthenticateNoLoginURLSkipped(t *testing.T) {
	cfg := &core.Config{UserAgent: "sxel-test"}
	client := core.NewHTTPClient(cfg)
	ok, err := Authenticate(client, cfg, AuthConfig{Username: "admin", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected skipped authentication when LoginURL empty")
	}
}
