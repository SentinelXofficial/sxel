package report

import (
	"encoding/json"
	"os"
	"sort"
	"time"
)

type ScanState struct {
	Generated string    `json:"generated"`
	Findings  []Finding `json:"findings"`
}

type Diff struct {
	Added   []Finding
	Fixed   []Finding
	Changed []Finding
	Same    int
}

func LoadState(path string) (*ScanState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s ScanState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func SaveState(path string, findings []Finding) error {
	s := ScanState{
		Generated: nowRFC(),
		Findings:  Dedupe(findings),
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func Compare(prev, curr []Finding) Diff {
	var d Diff
	prevMap := FingerprintMap(prev)
	currMap := FingerprintMap(curr)
	for fp, f := range currMap {
		if old, ok := prevMap[fp]; ok {
			if old.Severity != f.Severity {
				d.Changed = append(d.Changed, f)
			} else {
				d.Same++
			}
		} else {
			d.Added = append(d.Added, f)
		}
	}
	for fp, f := range prevMap {
		if _, ok := currMap[fp]; !ok {
			d.Fixed = append(d.Fixed, f)
		}
	}
	sort.Slice(d.Added, func(a, b int) bool { return d.Added[a].URL < d.Added[b].URL })
	sort.Slice(d.Fixed, func(a, b int) bool { return d.Fixed[a].URL < d.Fixed[b].URL })
	sort.Slice(d.Changed, func(a, b int) bool { return d.Changed[a].URL < d.Changed[b].URL })
	return d
}

func nowRFC() string {
	return time.Now().Format("2006-01-02T15:04:05Z07:00")
}
