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

type deserializePayload struct {
	Label       string
	Body        string
	ContentType string
	Markers     []string
	Engine      string
}

var phpDeserializePayloads = []deserializePayload{
	{
		Label:       "PHP serialized object (basic)",
		Body:        `O:8:"stdClass":1:{s:4:"test";s:4:"sxel";}`,
		ContentType: "application/x-www-form-urlencoded",
		Markers:     []string{"__PHP_Incomplete_Class", "unserialize", "O:8:", "s:4:", "incomplete_class"},
		Engine:      "PHP",
	},
	{
		Label:       "PHP serialized object (SplDoublyLinkedList)",
		Body:        `O:19:"SplDoublyLinkedList":2:{s:4:"test";s:4:"sxel";}`,
		ContentType: "application/x-www-form-urlencoded",
		Markers:     []string{"SplDoublyLinkedList", "unserialize"},
		Engine:      "PHP",
	},
	{
		Label:       "PHP serialized object (DateInterval)",
		Body:        `O:12:"DateInterval":1:{s:1:"y";i:1;}`,
		ContentType: "application/x-www-form-urlencoded",
		Markers:     []string{"DateInterval", "unserialize"},
		Engine:      "PHP",
	},
	{
		Label:       "PHP serialized — JSON content-type variant",
		Body:        `{"data":"O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"sxel\";}"}`,
		ContentType: "application/json",
		Markers:     []string{"__PHP_Incomplete_Class", "O:8:"},
		Engine:      "PHP",
	},
}

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
		Markers:     []string{"java.io.objectinputstream", "invalidclassexception", "streamcorruptedexception", "classnotfoundexception", "objectstreamexception"},
		Engine:      "Java",
	},
}

var pythonPicklePayloads = []deserializePayload{
	{
		Label:       "Python pickle (protocol 0)",
		Body:        "(dp0\nS'test'\np1\nS'sxel'\np2\ns.",
		ContentType: "application/octet-stream",
		Markers:     []string{"pickle", "unpickle", "KeyError", "AttributeError", "TypeError", "loads"},
		Engine:      "Python",
	},
	{
		Label:       "Python pickle — base64 encoded",
		Body:        base64.StdEncoding.EncodeToString([]byte("(dp0\nS'test'\np1\nS'sxel'\np2\ns.")),
		ContentType: "text/plain",
		Markers:     []string{"pickle", "unpickle", "KeyError", "AttributeError", "TypeError", "IndexError", "ValueError"},
		Engine:      "Python",
	},
}

var dotnetDeserializePayloads = []deserializePayload{
	{
		Label:       ".NET BinaryFormatter probe",
		Body:        "\x00\x01\x00\x00\x00\xff\xff\xff\xff",
		ContentType: "application/octet-stream",
		Markers:     []string{"BinaryFormatter", "SerializationException", "InvalidCastException", "Formatter"},
		Engine:      ".NET",
	},
}

func ScanDeserialize(client *http.Client, cfg *core.Config, target core.CrawlResult) []core.ScanResult {
	var results []core.ScanResult

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

		baseOK := true
		baseBody, baseStatus, err := doPOSTPlain(client, cfg, endpoint, "sxel=normal_baseline", "application/x-www-form-urlencoded")
		if err != nil {
			baseOK = false
		}
		baseBodyLow := strings.ToLower(baseBody)

		for _, pl := range allPayloads {
			body, status, err := doPOSTPlain(client, cfg, endpoint, pl.Body, pl.ContentType)
			if err != nil {
				continue
			}

			bodyClean := strings.ReplaceAll(body, pl.Body, "")
			bodyClean = strings.ReplaceAll(bodyClean, base64.StdEncoding.EncodeToString([]byte(pl.Body)), "")
			bodyLow := strings.ToLower(bodyClean)

			for _, marker := range pl.Markers {
				if !strings.Contains(bodyLow, strings.ToLower(marker)) {
					continue
				}
				if baseOK && strings.Contains(baseBodyLow, strings.ToLower(marker)) {
					continue
				}
				if !baseOK && status != 500 && status != 502 {
					continue
				}
				if genericExceptionMarker(marker) && status != 500 && status != 502 {
					continue
				}
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

	return results
}

func genericExceptionMarker(marker string) bool {
	switch strings.ToLower(marker) {
	case "keyerror", "attributeerror", "typeerror":
		return true
	}
	return false
}

func doPOSTPlain(client *http.Client, cfg *core.Config, rawURL, body, contentType string) (string, int, error) {
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
