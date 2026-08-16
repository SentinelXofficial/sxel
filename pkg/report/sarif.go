package report

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

func sarifLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	}
	return "none"
}

func sanitizeRuleID(s string) string {
	var b strings.Builder
	for _, c := range strings.ToUpper(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == ' ' || c == '-' || c == '_' || c == '(' || c == ')' || c == '/' || c == '—':
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		id = "GENERIC"
	}
	return id
}

func WriteSARIF(path string, findings []Finding, toolVersion string) error {
	rules := map[string]sarifRule{}
	results := []sarifResult{}
	for _, f := range findings {
		ruleID := "SXEL-" + sanitizeRuleID(f.Type)
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = sarifRule{
				ID:                   ruleID,
				Name:                 f.Type,
				ShortDescription:     sarifText{Text: f.Type},
				FullDescription:      sarifText{Text: f.Type},
				DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(f.Severity)},
			}
		}
		msg := f.Evidence
		if msg == "" {
			msg = f.Type + " at " + f.URL
		}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.URL},
					Region:           sarifRegion{StartLine: 1},
				},
			}},
			PartialFingerprints: map[string]string{
				"sxelFingerprint/v1": "sha256:" + Fingerprint(f),
			},
		})
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(a, b int) bool { return ruleList[a].ID < ruleList[b].ID })

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "sxel",
				Version:        toolVersion,
				InformationURI: "https://github.com/SentinelXofficial/sxel",
				Rules:          ruleList,
			}},
			Results:     results,
			Invocations: []sarifInvocation{{ExecutionSuccessful: true}},
		}},
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
