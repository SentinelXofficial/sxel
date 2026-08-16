package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func SendWebhook(url, kind, chatID, title string, findings []Finding, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}
	if client.Timeout == 0 {
		client.Timeout = 10 * time.Second
	}
	var payload []byte
	var err error
	switch strings.ToLower(kind) {
	case "telegram":
		payload, err = telegramPayload(chatID, title, findings)
	case "discord":
		payload, err = discordPayload(title, findings)
	default:
		payload, err = slackPayload(title, findings)
	}
	if err != nil {
		return err
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func buildSummary(title string, findings []Finding) string {
	var sb strings.Builder
	sb.WriteString(title)
	if len(findings) == 0 {
		sb.WriteString("\nNo findings.")
		return sb.String()
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			sb.WriteString(fmt.Sprintf("\n%s: %d", sev, n))
		}
	}
	sb.WriteString(fmt.Sprintf("\nTotal: %d finding(s)", len(findings)))
	limit := 8
	if len(findings) < limit {
		limit = len(findings)
	}
	for _, f := range findings[:limit] {
		line := f.Type + " " + f.URL
		if f.Parameter != "" {
			line += " [" + f.Parameter + "]"
		}
		sb.WriteString("\n- " + line)
	}
	if len(findings) > limit {
		sb.WriteString(fmt.Sprintf("\n... and %d more", len(findings)-limit))
	}
	return sb.String()
}

func slackPayload(title string, findings []Finding) ([]byte, error) {
	return json.Marshal(map[string]string{
		"text": buildSummary(title, findings),
	})
}

func discordPayload(title string, findings []Finding) ([]byte, error) {
	return json.Marshal(map[string]string{
		"content": buildSummary(title, findings),
	})
}

func telegramPayload(chatID, title string, findings []Finding) ([]byte, error) {
	return json.Marshal(map[string]string{
		"chat_id": chatID,
		"text":    buildSummary(title, findings),
	})
}
