package recon

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
)

func FaviconHash(client *http.Client, baseURL string) string {
	u := strings.TrimSuffix(baseURL, "/") + "/favicon.ico"
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sxel-recon/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || len(body) == 0 {
		return ""
	}
	enc := base64.StdEncoding.EncodeToString(body)
	h := int32(mmh3x86_32([]byte(enc), 0))
	return "favicon-hash:" + itoa(int(h))
}

func FaviconHashBytes(body []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(body)
	return int32(mmh3x86_32([]byte(enc), 0))
}
