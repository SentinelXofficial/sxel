package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SentinelXofficial/sxel/internal/output"
	"gopkg.in/yaml.v3"
)

type stringList []string

func (s *stringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*s = []string{n.Value}
		return nil
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
		*s = out
		return nil
	}
	return fmt.Errorf("unexpected YAML kind %d for string list", n.Kind)
}

type intList []int

func (s *intList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var v int
		if err := n.Decode(&v); err != nil {
			return err
		}
		*s = []int{v}
		return nil
	case yaml.SequenceNode:
		var out []int
		for _, c := range n.Content {
			var v int
			if err := c.Decode(&v); err != nil {
				return err
			}
			out = append(out, v)
		}
		*s = out
		return nil
	}
	return fmt.Errorf("unexpected YAML kind %d for int list", n.Kind)
}

type nucleiTemplate struct {
	ID   string       `yaml:"id"`
	Info nucleiInfo   `yaml:"info"`
	HTTP []nucleiHTTP `yaml:"http,omitempty"`
}

type nucleiInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        string   `yaml:"tags"`
	Reference   []string `yaml:"reference,omitempty"`
	Metadata    struct {
		MaxRequest int `yaml:"max-request,omitempty"`
	} `yaml:"metadata,omitempty"`
	Classification struct {
		CVSSScore float64 `yaml:"cvss-score,omitempty"`
		CVEID     string  `yaml:"cve-id,omitempty"`
	} `yaml:"classification,omitempty"`
}

type nucleiHTTP struct {
	Raw               stringList          `yaml:"raw,omitempty"`
	Method            string              `yaml:"method,omitempty"`
	Path              stringList          `yaml:"path,omitempty"`
	Headers           map[string]string   `yaml:"headers,omitempty"`
	Body              string              `yaml:"body,omitempty"`
	MatchersCondition string              `yaml:"matchers-condition,omitempty"`
	Matchers          []nucleiMatcher     `yaml:"matchers,omitempty"`
	Payloads          map[string][]string `yaml:"payloads,omitempty"`
}

type nucleiMatcher struct {
	Type      string     `yaml:"type"`
	Part      string     `yaml:"part,omitempty"`
	Words     stringList `yaml:"words,omitempty"`
	Regex     stringList `yaml:"regex,omitempty"`
	Status    intList    `yaml:"status,omitempty"`
	Condition string     `yaml:"condition,omitempty"`
}

type sxelTemplate struct {
	ID    string     `yaml:"id"`
	Brief sxelBrief  `yaml:"brief"`
	Moves []sxelMove `yaml:"moves"`
}

type sxelBrief struct {
	Title string   `yaml:"title"`
	By    string   `yaml:"by"`
	Level string   `yaml:"level"`
	About string   `yaml:"about"`
	Label []string `yaml:"label,omitempty"`
	Score string   `yaml:"score,omitempty"`
}

type sxelMove struct {
	Verb  string            `yaml:"verb"`
	To    []string          `yaml:"to"`
	Head  map[string]string `yaml:"head,omitempty"`
	Body  string            `yaml:"body,omitempty"`
	Signs []sxelSign        `yaml:"signs"`
}

type sxelSign struct {
	On     string   `yaml:"on"`
	Has    []string `yaml:"has,omitempty"`
	In     string   `yaml:"in,omitempty"`
	Need   string   `yaml:"need,omitempty"`
	Status []int    `yaml:"status,omitempty"`
}

func ConvertNucleiTemplates(srcDir, dstDir string) {
	var total, converted, skipped int
	skipDirs := map[string]bool{
		"headless": true, "dns": true, "ssl": true, "file": true,
		"javascript": true, "code": true, "workflows": true,
		"cloud": true, "helpers": true, "dast": true,
	}

	srcDir, _ = filepath.Abs(srcDir)
	dstDir, _ = filepath.Abs(dstDir)

	_ = os.MkdirAll(dstDir, 0755)

	_ = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if skipDirs[base] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") &&
			!strings.HasSuffix(strings.ToLower(info.Name()), ".yml") {
			return nil
		}

		total++

		data, err := os.ReadFile(path)
		if err != nil {
			skipped++
			return nil
		}

		var nt nucleiTemplate
		if err := yaml.Unmarshal(data, &nt); err != nil || nt.ID == "" {
			skipped++
			return nil
		}

		sx := convertNuclei(&nt)
		if sx == nil || len(sx.Moves) == 0 {
			skipped++
			return nil
		}

		rel, _ := filepath.Rel(srcDir, path)
		outPath := filepath.Join(dstDir, rel)

		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			skipped++
			return nil
		}

		outData, err := yaml.Marshal(sx)
		if err != nil {
			skipped++
			return nil
		}
		if err := os.WriteFile(outPath, outData, 0644); err != nil {
			skipped++
			return nil
		}

		converted++
		if total%50 == 0 {
			fmt.Printf("\r\033[K  converting... %d processed (%d converted, %d skipped)", total, converted, skipped)
		}
		return nil
	})

	fmt.Printf("\r\033[K")
	output.Success("Conversion done: %d processed → %d converted, %d skipped (no HTTP moves)", total, converted, skipped)
}

func convertNuclei(nt *nucleiTemplate) *sxelTemplate {
	if len(nt.HTTP) == 0 {
		return nil
	}

	sx := &sxelTemplate{
		ID: nt.ID,
		Brief: sxelBrief{
			Title: nt.Info.Name,
			By:    firstAuthor(nt.Info.Author),
			Level: mapSeverity(nt.Info.Severity),
			About: firstLine(nt.Info.Description),
			Score: formatScore(nt.Info.Classification.CVSSScore, nt.Info.Classification.CVEID),
		},
	}

	if nt.Info.Tags != "" {
		for _, t := range strings.Split(nt.Info.Tags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				sx.Brief.Label = append(sx.Brief.Label, t)
			}
		}
	}

	for _, h := range nt.HTTP {
		moves := convertHTTP(&h)
		sx.Moves = append(sx.Moves, moves...)
	}

	if len(sx.Moves) == 0 {
		return nil
	}
	return sx
}

func convertHTTP(h *nucleiHTTP) []sxelMove {
	var moves []sxelMove

	signs := convertMatchers(h.Matchers, h.MatchersCondition)

	for _, raw := range h.Raw {
		move := parseRawHTTP(raw)
		if move == nil {
			continue
		}
		move.Signs = signs
		moves = append(moves, *move)
	}

	if len(h.Raw) == 0 && (h.Method != "" || len(h.Path) > 0) {
		method := strings.ToUpper(h.Method)
		if method == "" {
			method = "GET"
		}
		paths := expandPayloads(h.Path, h.Payloads)
		if len(paths) == 0 {
			paths = []string{"{{BaseURL}}/"}
		}
		moves = append(moves, sxelMove{
			Verb:  method,
			To:    paths,
			Head:  h.Headers,
			Body:  h.Body,
			Signs: signs,
		})
	}

	return moves
}

func expandPayloads(paths []string, payloads map[string][]string) []string {
	if len(payloads) == 0 {
		return paths
	}
	var names []string
	for n := range payloads {
		names = append(names, n)
	}
	sort.Strings(names)
	keyToIdx := make(map[string]int, len(names))
	for i, n := range names {
		keyToIdx[n] = i
	}
	var combos [][]string
	combos = append(combos, make([]string, len(names)))
	for _, n := range names {
		vals := payloads[n]
		if len(vals) == 0 {
			continue
		}
		idx := keyToIdx[n]
		var next [][]string
		for _, c := range combos {
			for _, v := range vals {
				cc := append([]string{}, c...)
				cc[idx] = v
				next = append(next, cc)
			}
		}
		combos = next
		if len(combos) > 512 {
			combos = combos[:512]
		}
	}
	var out []string
	for _, combo := range combos {
		for _, p := range paths {
			expanded := p
			for n, idx := range keyToIdx {
				expanded = strings.ReplaceAll(expanded, "{{"+n+"}}", combo[idx])
			}
			if !containsString(out, expanded) {
				out = append(out, expanded)
			}
		}
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func parseRawHTTP(raw string) *sxelMove {
	lines := strings.Split(raw, "\n")

	if len(lines) == 0 {
		return nil
	}
	reqLine := strings.TrimSpace(lines[0])
	parts := strings.SplitN(reqLine, " ", 3)
	if len(parts) < 2 {
		return nil
	}
	verb := strings.ToUpper(parts[0])
	path := parts[1]

	if verb != "GET" && verb != "POST" && verb != "PUT" && verb != "DELETE" &&
		verb != "PATCH" && verb != "HEAD" && verb != "OPTIONS" {
		return nil
	}

	target := path
	if !strings.Contains(path, "{{BaseURL}}") {
		target = "{{BaseURL}}" + path
	}
	move := &sxelMove{
		Verb: verb,
		To:   []string{target},
		Head: make(map[string]string),
	}

	inBody := false
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if !inBody && line == "" {
			inBody = true
			continue
		}
		if inBody {
			move.Body += line + "\n"
		} else {
			kv := strings.SplitN(line, ":", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				val := strings.TrimSpace(kv[1])
				if strings.EqualFold(key, "Host") {
					continue
				}
				move.Head[key] = val
			}
		}
	}

	move.Body = strings.TrimRight(move.Body, "\n")
	return move
}

func convertMatchers(matchers []nucleiMatcher, condition string) []sxelSign {
	var signs []sxelSign
	all := strings.EqualFold(strings.TrimSpace(condition), "and")

	for _, m := range matchers {
		sign := sxelSign{}
		if all {
			sign.Need = "all"
		}

		switch m.Type {
		case "word":
			sign.On = "word"
			sign.Has = m.Words
			sign.In = m.Part
			if sign.In == "" {
				sign.In = "body"
			}
			if m.Condition == "and" {
				sign.Need = "all"
			}
		case "status":
			sign.On = "status"
			sign.Status = m.Status
		case "regex":
			sign.On = "word"
			var words []string
			for _, r := range m.Regex {
				r = strings.TrimPrefix(r, "^")
				r = strings.TrimSuffix(r, "$")
				r = strings.ReplaceAll(r, "\\", "")
				if !strings.ContainsAny(r, ".*+?{}[]()|") {
					words = append(words, r)
				}
			}
			if len(words) == 0 {
				continue
			}
			sign.Has = words
			sign.In = m.Part
			if sign.In == "" {
				sign.In = "body"
			}
		default:
			continue
		}

		signs = append(signs, sign)
	}

	return signs
}

func mapSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func firstAuthor(author string) string {
	if author == "" {
		return "nuclei"
	}
	if idx := strings.Index(author, ","); idx > 0 {
		return author[:idx]
	}
	return author
}

func firstLine(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			if len(l) > 200 {
				r := []rune(l)
				if len(r) > 197 {
					r = r[:197]
				}
				l = string(r) + "..."
			}
			return l
		}
	}
	return ""
}

func formatScore(cvss float64, cve string) string {
	var parts []string
	if cve != "" {
		parts = append(parts, cve)
	}
	if cvss > 0 {
		parts = append(parts, fmt.Sprintf("CVSS:%.1f", cvss))
	}
	return strings.Join(parts, " ")
}
