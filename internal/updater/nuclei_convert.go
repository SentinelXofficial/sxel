package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/SentinelXofficial/sxel/internal/output"
	"gopkg.in/yaml.v3"
)

// ── Nuclei YAML structures (partial — only fields we convert) ──────────────────

type nucleiTemplate struct {
	ID   string      `yaml:"id"`
	Info nucleiInfo  `yaml:"info"`
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
	Raw     []string        `yaml:"raw,omitempty"`
	Method  string          `yaml:"method,omitempty"`
	Path    []string        `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string          `yaml:"body,omitempty"`
	MatchersCondition string     `yaml:"matchers-condition,omitempty"`
	Matchers          []nucleiMatcher `yaml:"matchers,omitempty"`
}

type nucleiMatcher struct {
	Type   string   `yaml:"type"`
	Part   string   `yaml:"part,omitempty"`
	Words  []string `yaml:"words,omitempty"`
	Regex  []string `yaml:"regex,omitempty"`
	Status []int    `yaml:"status,omitempty"`
	Condition string `yaml:"condition,omitempty"`
}

// ── sxel output structures ─────────────────────────────────────────────────────

type sxelTemplate struct {
	ID    string        `yaml:"id"`
	Brief sxelBrief     `yaml:"brief"`
	Moves []sxelMove    `yaml:"moves"`
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

// ── Public API ─────────────────────────────────────────────────────────────────

// ConvertNucleiTemplates reads Nuclei YAML templates from srcDir and writes
// converted sxel-format templates into dstDir, preserving the category
// subdirectory structure.
func ConvertNucleiTemplates(srcDir, dstDir string) {
	// Walk nuclei template directory (skip non-template categories)
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

		// Read Nuclei template
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var nt nucleiTemplate
		if err := yaml.Unmarshal(data, &nt); err != nil || nt.ID == "" {
			return nil
		}

		// Convert
		sx := convertNuclei(&nt)
		if sx == nil || len(sx.Moves) == 0 {
			skipped++
			return nil
		}

		// Determine relative path from srcDir, keep category structure
		rel, _ := filepath.Rel(srcDir, path)
		outPath := filepath.Join(dstDir, rel)

		_ = os.MkdirAll(filepath.Dir(outPath), 0755)

		outData, _ := yaml.Marshal(sx)
		_ = os.WriteFile(outPath, outData, 0644)

		converted++
		if total%50 == 0 {
			fmt.Printf("\r\033[K  converting... %d processed (%d converted, %d skipped)", total, converted, skipped)
		}
		return nil
	})

	fmt.Printf("\r\033[K")
	output.Success("Conversion done: %d processed → %d converted, %d skipped (no HTTP moves)", total, converted, skipped)
}

// ── internals ──────────────────────────────────────────────────────────────────

func convertNuclei(nt *nucleiTemplate) *sxelTemplate {
	if len(nt.HTTP) == 0 {
		return nil
	}

	// Build sxel template
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

	// Parse tags → labels
	if nt.Info.Tags != "" {
		for _, t := range strings.Split(nt.Info.Tags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				sx.Brief.Label = append(sx.Brief.Label, t)
			}
		}
	}

	// Convert each HTTP probe
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

	// Build sxel signs from matchers once (shared across raw requests)
	signs := convertMatchers(h.Matchers, h.MatchersCondition)

	// Handle raw HTTP requests (most common format)
	for _, raw := range h.Raw {
		move := parseRawHTTP(raw)
		if move == nil {
			continue
		}
		move.Signs = signs
		moves = append(moves, *move)
	}

	// Handle structured method+path format (fallback)
	if len(h.Raw) == 0 && (h.Method != "" || len(h.Path) > 0) {
		method := strings.ToUpper(h.Method)
		if method == "" {
			method = "GET"
		}
		paths := h.Path
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

// parseRawHTTP parses a raw HTTP request string like:
//
//	GET /path HTTP/1.1
//	Host: {{Hostname}}
//	X-Custom: value
//
//	body content
func parseRawHTTP(raw string) *sxelMove {
	lines := strings.Split(raw, "\n")

	// First line: METHOD /path HTTP/1.1
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

	// Skip if verb is not HTTP
	if verb != "GET" && verb != "POST" && verb != "PUT" && verb != "DELETE" &&
		verb != "PATCH" && verb != "HEAD" && verb != "OPTIONS" {
		return nil
	}

	move := &sxelMove{
		Verb: verb,
		To:   []string{"{{BaseURL}}" + path},
		Head: make(map[string]string),
	}

	// Parse headers and body
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
				// Skip Host header (sxel sets it automatically)
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

	for _, m := range matchers {
		sign := sxelSign{}

		switch m.Type {
		case "word":
			sign.On = "word"
			sign.Has = m.Words
			sign.In = m.Part
			if sign.In == "" {
				sign.In = "body"
			}
			if condition == "and" || m.Condition == "and" {
				sign.Need = "all"
			}
		case "status":
			sign.On = "status"
			sign.Status = m.Status
		case "regex":
			// Convert regex patterns to word patterns where possible
			sign.On = "word"
			var words []string
			for _, r := range m.Regex {
				// Extract literal substrings from simple regexes
				r = strings.TrimPrefix(r, "^")
				r = strings.TrimSuffix(r, "$")
				r = strings.ReplaceAll(r, "\\", "")
				if !strings.ContainsAny(r, ".*+?{}[]()|") {
					words = append(words, r)
				}
			}
			if len(words) == 0 {
				continue // skip complex regexes
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

// ── helpers ────────────────────────────────────────────────────────────────────

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
	// Trim leading/trailing whitespace and take first non-empty line
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			if len(l) > 200 {
				l = l[:197] + "..."
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
