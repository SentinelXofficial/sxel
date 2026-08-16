package core

import (
	"bytes"
	"fmt"
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

const maxBodySize = 10 << 20

func ReadBody(r io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(r, maxBodySize))
	if err != nil {
		return string(b)
	}
	return string(b)
}

func do(client *http.Client, cfg *Config, req *http.Request) (*http.Response, error) {
	if client == nil {
		client = &http.Client{}
	}
	if req.Body != nil && req.GetBody == nil {
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		buf := bytes.NewReader(body)
		req.Body = io.NopCloser(buf)
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 429 {
			return resp, nil
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cfg.Limiter.Adapt429()
		if req.GetBody != nil {
			if rb, berr := req.GetBody(); berr == nil {
				req.Body = rb
			}
		}
	}
	return nil, fmt.Errorf("target rate limited: retries exhausted")
}

func DoGET(client *http.Client, cfg *Config, rawURL string) (string, int, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	ApplyHeaders(req, cfg)
	resp, err := do(client, cfg, req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	return ReadBody(resp.Body), resp.StatusCode, nil
}

func DoPOST(client *http.Client, cfg *Config, rawURL string, data url.Values) (string, int, error) {
	req, err := http.NewRequest("POST", rawURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, err
	}
	ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := do(client, cfg, req)
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

func isHexChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func EscapeRawQueryValue(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'),
			c == '-', c == '_', c == '.', c == '~', c == '!', c == '*', c == '\'', c == '(',
			c == ')', c == ';', c == ':', c == '@', c == ',', c == '$':
			b.WriteByte(c)
		case c == '%' && i+2 < len(v) && isHexChar(v[i+1]) && isHexChar(v[i+2]):
			b.WriteByte(c)
			b.WriteByte(v[i+1])
			b.WriteByte(v[i+2])
			i += 2
		case c == ' ':
			b.WriteString("%20")
		default:
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

func SetParamRaw(rawURL, param, value string) (string, error) {
	p, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	prefix := param + "="
	var parts []string
	for _, seg := range strings.Split(p.RawQuery, "&") {
		if seg == "" {
			continue
		}
		key := seg
		if i := strings.IndexByte(seg, '='); i >= 0 {
			key = seg[:i]
		}
		if dk, err := url.QueryUnescape(key); err == nil {
			if dk == param {
				continue
			}
		} else if key == param {
			continue
		}
		parts = append(parts, seg)
	}
	parts = append(parts, prefix+EscapeRawQueryValue(value))
	p.RawQuery = strings.Join(parts, "&")
	return p.String(), nil
}

func SetFormParams(rawURL string, params url.Values) (string, error) {
	p, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := p.Query()
	for k, vals := range params {
		q.Del(k)
		for _, v := range vals {
			q.Add(k, v)
		}
	}
	p.RawQuery = q.Encode()
	return p.String(), nil
}

func FormDefaults(f Form) url.Values {
	v := url.Values{}
	for _, inp := range f.Inputs {
		if inp.Name == "" {
			continue
		}
		if inp.Value != "" {
			v.Set(inp.Name, inp.Value)
			continue
		}
		val := "test"
		switch strings.ToLower(inp.Type) {
		case "email":
			val = "admin@example.com"
		case "number", "tel":
			val = "123456"
		case "password":
			val = "Test1234!"
		case "search":
			val = "fuzz"
		}
		v.Set(inp.Name, val)
	}
	if f.TokenName != "" && f.TokenValue != "" {
		v.Set(f.TokenName, f.TokenValue)
	}
	return v
}

func StripQuery(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func DoXMLPOST(client *http.Client, cfg *Config, rawURL, body, contentType string) (string, int, error) {
	req, err := http.NewRequest("POST", rawURL, bytes.NewBufferString(body))
	if err != nil {
		return "", 0, err
	}
	ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", contentType)
	resp, err := do(client, cfg, req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b := ReadBody(resp.Body)
	return b, resp.StatusCode, nil
}

func DoJSONPOST(client *http.Client, cfg *Config, rawURL, jsonBody string) (string, int, error) {
	req, err := http.NewRequest("POST", rawURL, bytes.NewBufferString(jsonBody))
	if err != nil {
		return "", 0, err
	}
	ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/json")
	resp, err := do(client, cfg, req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b := ReadBody(resp.Body)
	return b, resp.StatusCode, nil
}

func DoJSONPostRaw(client *http.Client, cfg *Config, rawURL, jsonBody string) (string, int, error) {
	return DoJSONPOST(client, cfg, rawURL, jsonBody)
}

func DoPOSTPlain(client *http.Client, cfg *Config, rawURL, body, contentType string) (string, int, error) {
	return DoXMLPOST(client, cfg, rawURL, body, contentType)
}
