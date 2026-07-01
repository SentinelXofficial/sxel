package core

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func ApplyHeaders(req *http.Request, cfg *Config) {
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
}

// maxBodySize caps response bodies read into memory (10 MB).
const maxBodySize = 10 << 20

// readBody is a safe io.ReadAll replacement that enforces a size limit.
// It returns the body as a string; if the read fails, an empty string is
// returned (the caller should treat this as a soft failure).
func ReadBody(r io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(r, maxBodySize))
	if err != nil {
		return ""
	}
	return string(b)
}

func DoGET(client *http.Client, cfg *Config, rawURL string) (string, int, error) {
	cfg.Limiter.Wait() // no-op if Limiter is nil
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	ApplyHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	return ReadBody(resp.Body), resp.StatusCode, nil
}

func DoPOST(client *http.Client, cfg *Config, rawURL string, data url.Values) (string, int, error) {
	cfg.Limiter.Wait() // no-op if Limiter is nil
	req, err := http.NewRequest("POST", rawURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, err
	}
	ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	return ReadBody(resp.Body), resp.StatusCode, nil
}

func SetParam(rawURL, param, value string) (string, error) {
	p, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := p.Query()
	q.Set(param, value)
	p.RawQuery = q.Encode()
	return p.String(), nil
}

func FormDefaults(f Form) url.Values {
	v := url.Values{}
	for _, inp := range f.Inputs {
		if inp.Value != "" {
			v.Set(inp.Name, inp.Value)
		} else {
			v.Set(inp.Name, "test")
		}
	}
	return v
}



// ScanSQLi moved to pkg/modules


// ScanXSS moved to pkg/modules


// StripQuery removes the query string and fragment from a URL.
func StripQuery(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// DoXMLPOST sends a raw XML body with the given content-type.
func DoXMLPOST(client *http.Client, cfg *Config, rawURL, body, contentType string) (string, int, error) {
	cfg.Limiter.Wait()
	req, err := http.NewRequest("POST", rawURL, bytes.NewBufferString(body))
	if err != nil {
		return "", 0, err
	}
	ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b := ReadBody(resp.Body)
	return b, resp.StatusCode, nil
}

// DoJSONPOST sends a raw JSON body to rawURL.
func DoJSONPOST(client *http.Client, cfg *Config, rawURL, jsonBody string) (string, int, error) {
	cfg.Limiter.Wait()
	req, err := http.NewRequest("POST", rawURL, bytes.NewBufferString(jsonBody))
	if err != nil {
		return "", 0, err
	}
	ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b := ReadBody(resp.Body)
	return b, resp.StatusCode, nil
}

// DoJSONPostRaw sends arbitrary JSON bytes as a POST request.
func DoJSONPostRaw(client *http.Client, cfg *Config, rawURL, jsonBody string) (string, int, error) {
	return DoJSONPOST(client, cfg, rawURL, jsonBody)
}

// DoPOSTPlain sends a raw body with the given content-type to a URL.
func DoPOSTPlain(client *http.Client, cfg *Config, rawURL, body, contentType string) (string, int, error) {
	return DoXMLPOST(client, cfg, rawURL, body, contentType)
}
