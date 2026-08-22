package engine

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
)

type AuthConfig struct {
	LoginURL  string
	Username  string
	Password  string
	UserField string
	PassField string
	VerifyURL string
}

func Authenticate(client *http.Client, cfg *core.Config, ac AuthConfig) (bool, error) {
	if ac.LoginURL == "" || ac.Username == "" {
		return false, nil
	}

	loginPage, status, err := core.DoGET(client, cfg, ac.LoginURL)
	if err != nil {
		return false, fmt.Errorf("failed to fetch login page: %v", err)
	}
	if status >= 400 {
		return false, fmt.Errorf("login page returned HTTP %d", status)
	}

	forms := ExtractForms(loginPage, ac.LoginURL)
	form := pickLoginForm(forms, ac)
	if form == nil {
		form = &core.Form{Action: ac.LoginURL, Method: "POST"}
	}

	action := form.Action
	if action == "" {
		action = ac.LoginURL
	}
	action = ResolveURL(mustParse(ac.LoginURL), action)

	data := core.FormDefaults(*form)
	userField := ac.UserField
	if userField == "" {
		userField = "username"
	}
	passField := ac.PassField
	if passField == "" {
		passField = "password"
	}
	data.Set(userField, ac.Username)
	data.Set(passField, ac.Password)

	method := strings.ToUpper(form.Method)
	if method == "" || method == "GET" {
		method = "POST"
	}

	req, err := http.NewRequest(method, action, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return false, err
	}
	core.ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("login POST failed: %v", err)
	}
	core.ReadBody(resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return false, fmt.Errorf("login POST returned HTTP %d — credentials likely rejected", resp.StatusCode)
	}

	verifyURL := ac.VerifyURL
	if verifyURL == "" {
		verifyURL = ac.LoginURL
	}
	vBody, vStatus, err := core.DoGET(client, cfg, verifyURL)
	if err != nil {
		return false, fmt.Errorf("auth verification failed: %v", err)
	}
	if vStatus >= 400 {
		return false, fmt.Errorf("auth verification returned HTTP %d — cannot confirm session", vStatus)
	}

	stillLogin := looksLikeLoginPage(vBody, userField, passField) && sameFormStillServed(vBody, verifyURL, action)
	if stillLogin {
		if cfg.Verbose {
			output.Verbose("[auth] login page still served after POST — session may not be authenticated")
		}
		return false, nil
	}

	if cfg.Verbose {
		output.Verbose("[auth] authenticated OK: login %s -> verify %s (HTTP %d, %d bytes)", ac.LoginURL, verifyURL, vStatus, len(vBody))
	}
	return true, nil
}

func pickLoginForm(forms []core.Form, ac AuthConfig) *core.Form {
	for i := range forms {
		f := &forms[i]
		hasPass := false
		hasUser := false
		for _, inp := range f.Inputs {
			lower := strings.ToLower(inp.Type)
			if lower == "password" || strings.Contains(strings.ToLower(inp.Name), "password") {
				hasPass = true
			}
			if strings.Contains(strings.ToLower(inp.Name), "user") || strings.Contains(strings.ToLower(inp.Name), "email") || strings.Contains(strings.ToLower(inp.Name), "login") {
				hasUser = true
			}
		}
		if hasPass && hasUser {
			return f
		}
	}
	for i := range forms {
		f := &forms[i]
		for _, inp := range f.Inputs {
			if strings.ToLower(inp.Type) == "password" {
				return f
			}
		}
	}
	return nil
}

func looksLikeLoginPage(body, userField, passField string) bool {
	low := strings.ToLower(body)
	u := strings.ToLower(userField)
	p := strings.ToLower(passField)
	if p != "" && (strings.Contains(low, "name=\""+p+"\"") || strings.Contains(low, "name='"+p+"'") || strings.Contains(low, "name="+p)) {
		return true
	}
	if u != "" && (strings.Contains(low, "name=\""+u+"\"") || strings.Contains(low, "name='"+u+"'") || strings.Contains(low, "name="+u)) {
		return true
	}
	hasPassInput := strings.Contains(low, "type=\"password\"") || strings.Contains(low, "type='password'")
	hasLoginForm := strings.Contains(low, "<form") && (strings.Contains(low, "login") || strings.Contains(low, "signin") || strings.Contains(low, "sign-in"))
	return hasPassInput && hasLoginForm
}

// sameFormStillServed reports whether the verify page still renders the login
// form we just submitted (same resolved action). Dashboards that merely embed
// a change-password form or "Login" nav links must not count as still-logged-
// out.
func sameFormStillServed(body, pageURL, submittedAction string) bool {
	forms := ExtractForms(body, pageURL)
	lf := pickLoginForm(forms, AuthConfig{})
	if lf == nil {
		return false
	}
	resolved := ResolveURL(mustParse(pageURL), lf.Action)
	return strings.EqualFold(resolved, submittedAction)
}

func mustParse(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		return &url.URL{}
	}
	return u
}
