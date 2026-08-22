package core

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type SessionJar struct {
	mu      sync.Mutex
	hosts   map[string]map[string]*http.Cookie
	domains map[string]map[string]*http.Cookie
}

func NewSessionJar(seed string) *SessionJar {
	return &SessionJar{hosts: map[string]map[string]*http.Cookie{}, domains: map[string]map[string]*http.Cookie{}}
}

func cookieExpired(c *http.Cookie) bool {
	if c.MaxAge < 0 {
		return true
	}
	if !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
		return true
	}
	return false
}

func cookiePathOK(c *http.Cookie, reqPath string) bool {
	p := c.Path
	if p == "" {
		p = "/"
	}
	if reqPath == "" {
		reqPath = "/"
	}
	return reqPath == p || strings.HasPrefix(reqPath, strings.TrimSuffix(p, "/")+"/")
}

func domainMatches(host, domain string) bool {
	if domain == "" {
		return true
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func validCookieDomain(host, domain string) bool {
	if domain == "" {
		return true
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	return domainMatches(host, domain)
}

func cookieKey(c *http.Cookie) string {
	p := c.Path
	if p == "" {
		p = "/"
	}
	return c.Name + "\x00" + p
}

func (j *SessionJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if j == nil {
		return
	}
	host := strings.ToLower(u.Hostname())
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		domain := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(c.Domain, ".")))
		if domain != "" && !validCookieDomain(host, domain) {
			domain = ""
		}
		var m map[string]*http.Cookie
		if domain != "" {
			m = j.domains[domain]
			if m == nil {
				m = map[string]*http.Cookie{}
				j.domains[domain] = m
			}
		} else {
			m = j.hosts[host]
			if m == nil {
				m = map[string]*http.Cookie{}
				j.hosts[host] = m
			}
		}
		key := cookieKey(c)
		if c.Value == "" || cookieExpired(c) {
			// Empty value is treated as a server-side deletion request
			// (documented by TestSessionJarDelete); expired cookies are
			// dropped per RFC 6265.
			delete(m, key)
			continue
		}
		m[key] = c
	}
}

func (j *SessionJar) Cookies(u *url.URL) []*http.Cookie {
	if j == nil {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	reqPath := u.Path
	if reqPath == "" {
		reqPath = "/"
	}
	secure := strings.EqualFold(u.Scheme, "https")
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*http.Cookie, 0, 4)
	if m := j.hosts[host]; m != nil {
		for _, c := range m {
			if cookieExpired(c) || !cookiePathOK(c, reqPath) || (c.Secure && !secure) {
				continue
			}
			out = append(out, c)
		}
	}
	for d, m := range j.domains {
		if !domainMatches(host, d) {
			continue
		}
		for _, c := range m {
			if cookieExpired(c) || !cookiePathOK(c, reqPath) || (c.Secure && !secure) {
				continue
			}
			out = append(out, c)
		}
	}
	return out
}
