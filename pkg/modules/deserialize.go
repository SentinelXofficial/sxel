package modules

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net/http"
	"strings"
	"time"
)

// deserializePayload groups payloads for a specific deserialization target.
type deserializePayload struct {
	Label       string
	Body        string
	ContentType string
	Markers     []string // response markers indicating vulnerability
	Engine      string
}

// PHP serialized object payloads — trigger __wakeup / __destruct magic methods.
var phpDeserializePayloads = []deserializePayload{
	{
		Label:       "PHP serialized object (basic)",
		Body:        `O:8:"stdClass":1:{s:4:"test";s:4:"sxsc";}`,
		ContentType: "application/x-www-form-urlencoded",
		Markers:     []string{"__PHP_Incomplete_Class", "unserialize", "O:8:", "s:4:", "incomplete_class"},
		Engine:      "PHP",
	},
	{
		Label:       "PHP serialized object (SplDoublyLinkedList)",
		Body:        `O:19:"SplDoublyLinkedList":2:{s:4:"test";s:4:"sxsc";}`,
		ContentType: "application/x-www-form-urlencoded",
		Markers:     []string{"SplDoublyLinkedList", "unserialize", "Exception"},
		Engine:      "PHP",
	},
	{
		Label:       "PHP serialized object (DateInterval)",
		Body:        `O:12:"DateInterval":1:{s:1:"y";i:1;}`,
		ContentType: "application/x-www-form-urlencoded",
		Markers:     []string{"DateInterval", "Exception", "unserialize"},
		Engine:      "PHP",
	},
	{
		Label:       "PHP serialized — JSON content-type variant",
		Body:        `{"data":"O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"sxsc\";}"}`,
		ContentType: "application/json",
		Markers:     []string{"__PHP_Incomplete_Class", "O:8:"},
		Engine:      "PHP",
	},
}

// Java deserialization markers (ysoserial-style — we send a small crafted payload)
var javaDeserializePayloads = []deserializePayload{
	{
		Label:       "Java serialized object (AC ED marker)",
		Body:        "\xac\xed\x00\x05test",
		ContentType: "application/octet-stream",
		Markers:     []string{"java.io", "ObjectInputStream", "ClassNotFoundException", "InvalidClassException", "StreamCorrupted"},
		Engine:      "Java",
	},
	{
		Label:       "Java serialized — JSON wrapper",
		Body:        `{"object":"` + base64.StdEncoding.EncodeToString([]byte("\xac\xed\x00\x05sr\x00")) + `"}`,
		ContentType: "application/json",
		Markers:     []string{"java", "deserializ", "exception", "invalid"},
		Engine:      "Java",
	},
}

// Python pickle payload markers
var pythonPicklePayloads = []deserializePayload{
	{
		Label:       "Python pickle (protocol 0)",
		Body:        "(dp0\nS'test'\np1\nS'sxsc'\np2\ns.",
		ContentType: "application/octet-stream",
		Markers:     []string{"pickle", "unpickle", "KeyError", "AttributeError", "TypeError", "loads"},
		Engine:      "Python",
	},
	{
		Label:       "Python pickle — base64 encoded",
		Body:        base64.StdEncoding.EncodeToString([]byte("(dp0\nS'test'\np1\nS'sxsc'\np2\ns.")),
		ContentType: "text/plain",
		Markers:     []string{"pickle", "unpickle", "error"},
		Engine:      "Python",
	},
}

// .NET BinaryFormatter markers
var dotnetDeserializePayloads = []deserializePayload{
	{
		Label:       ".NET BinaryFormatter probe",
		Body:        "\x00\x01\x00\x00\x00\xff\xff\xff\xff",
		ContentType: "application/octet-stream",
		Markers:     []string{"BinaryFormatter", "SerializationException", "InvalidCastException", "Formatter"},
		Engine:      ".NET",
	},
}

// ScanDeserialize probes POST endpoints for insecure deserialization across
// PHP, Java, Python, and .NET runtimes.
func ScanDeserialize(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

	// Collect POST endpoints
	postEndpoints := map[string]bool{target.URL: true}
	for _, form := range target.Forms {
		if strings.ToUpper(form.Method) == "POST" && form.Action != "" {
			postEndpoints[form.Action] = true
		}
	}

	allPayloads := append(phpDeserializePayloads, javaDeserializePayloads...)
	allPayloads = append(allPayloads, pythonPicklePayloads...)
	allPayloads = append(allPayloads, dotnetDeserializePayloads...)

	for endpoint := range postEndpoints {
		if cfg.Verbose {
			output.Verbose("[deserialize] probing %s", endpoint)
		}

		// Baseline: normal POST to get reference behavior.
		// We compare each probe response against this baseline to filter out
		// error markers that appear in normal (non-injected) responses, reducing
		// false positives from verbose error pages.
		baseBody, baseStatus, err := doPOSTPlain(client, cfg, endpoint, "sxsc=normal_baseline", "application/x-www-form-urlencoded")
		if err != nil {
			continue
		}
		baseBodyLow := strings.ToLower(baseBody)

		for _, pl := range allPayloads {
			body, status, err := doPOSTPlain(client, cfg, endpoint, pl.Body, pl.ContentType)
			if err != nil {
				continue
			}

			bodyLow := strings.ToLower(body)

			// Check for error markers that indicate deserialization processing,
			// but only if they were NOT already present in the baseline response
			for _, marker := range pl.Markers {
				if strings.Contains(bodyLow, strings.ToLower(marker)) &&
					!strings.Contains(baseBodyLow, strings.ToLower(marker)) {
					results = append(results, core.ScanResult{
						Type:      fmt.Sprintf("Insecure Deserialization [%s]", pl.Engine),
						URL:       endpoint,
						Method:    "POST",
						Parameter: "body",
						Payload:   pl.Label,
						Severity:  "CRITICAL",
						Evidence:  fmt.Sprintf("marker %q in response indicates deserialization processing (HTTP %d, baseline HTTP %d)", marker, status, baseStatus),
						Timestamp: time.Now(),
					})
					break
				}
			}
		}
	}

	return results
}

// doPOSTPlain sends a raw body with the given content-type to a URL.
// Uses core.ReadBody which enforces a 10 MB size limit to prevent OOM.
func doPOSTPlain(client *http.Client, cfg *core.Config, rawURL, body, contentType string) (string, int, error) {
	cfg.Limiter.Wait()
	req, err := http.NewRequest("POST", rawURL, bytes.NewBufferString(body))
	if err != nil {
		return "", 0, err
	}
	core.ApplyHeaders(req, cfg)
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b := core.ReadBody(resp.Body)
	return b, resp.StatusCode, nil
}
