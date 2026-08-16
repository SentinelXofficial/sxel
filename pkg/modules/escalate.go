package modules

import (
	"net/url"
	"strings"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

var severityLadder = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

var authPathHints = []string{
	"login", "signin", "sign-in", "auth", "account", "password", "passwd",
	"register", "signup", "admin", "session", "forgot", "reset",
}

func isAuthPath(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	path := strings.ToLower(p.Path)
	for _, h := range authPathHints {
		if strings.Contains(path, h) {
			return true
		}
	}
	return false
}

func bumpSeverity(sev string) string {
	for i, s := range severityLadder {
		if s == sev && i < len(severityLadder)-1 {
			return severityLadder[i+1]
		}
	}
	return sev
}

func EscalateSeverity(res core.ScanResult) core.ScanResult {
	if !isAuthPath(res.URL) {
		return res
	}
	switch res.Severity {
	case "LOW", "MEDIUM", "HIGH":
		res.Severity = bumpSeverity(res.Severity)
	}
	return res
}
