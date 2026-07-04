package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/color"
)

const tsFormat = "2006-01-02 15:04:05"

func now() string { return time.Now().Format(tsFormat) }

// ── Status messages ──────────────────────────────────────────────────────────

// Info prints a cyan [INFO] line with timestamp.
func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s %s\n", color.Cyan("[INFO]"), color.Gray(now()), msg)
}

// Warn prints a yellow [WARN] line with timestamp.
func Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s %s\n", color.BoldYellow("[WARN]"), color.Gray(now()), msg)
}

// Error prints a red [ERROR] line with timestamp.
func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s %s\n", color.BoldRed("[ERROR]"), color.Gray(now()), msg)
}

// Success prints a green [+] line with timestamp.
func Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s %s\n", color.Green("[+]"), color.Gray(now()), msg)
}

// Debug prints a gray [DEBUG] line with timestamp.
func Debug(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s %s\n", color.Gray("[DEBUG]"), color.Gray(now()), msg)
}

// Plain prints a line without any tag or timestamp (for ASCII art, etc.).
func Plain(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

// Status prints a cyan [*] line with timestamp — for lifecycle events like
// "Preparing Engine", "Downloading templates", etc.
func Status(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s %s\n", color.Cyan("[*]"), color.Gray(now()), msg)
}

// Separator prints a horizontal rule.
func Separator() {
	fmt.Println("────────────────────────────────────────────────────────────")
}

// ── Progress ─────────────────────────────────────────────────────────────────

// Progress prints a self-overwriting progress line (no \n — uses \r).
func Progress(scanned, pending int, sent int64, latency time.Duration, failedRatio float64) {
	fmt.Printf("\r\033[K%s scanned: %d, pending: %d, requestSent: %d, latency: %v, failedRatio: %.1f%%",
		color.Cyan("[*]"), scanned, pending, sent, latency.Round(time.Millisecond), failedRatio)
}

// ── Findings ─────────────────────────────────────────────────────────────────

// VulnInline prints a one-line vulnerability finding with timestamp.
// vulnType is the short tag like "SQLI", "XSS", "SSRF".
func VulnInline(vulnType string, format string, args ...interface{}) {
	detail := fmt.Sprintf(format, args...)
	tag := fmt.Sprintf("[%-6s]", vulnType)
	fmt.Printf("%s %s %s %s\n", color.BoldRed("[VULN]"), color.Gray(now()), color.Yellow(tag), detail)
}

// SuspectInline prints a one-line SUSPECT finding for unconfirmed issues.
func SuspectInline(vulnType string, format string, args ...interface{}) {
	detail := fmt.Sprintf(format, args...)
	tag := fmt.Sprintf("[%-6s]", vulnType)
	fmt.Printf("%s %s %s %s\n", color.BoldYellow("[?]"), color.Gray(now()), color.Yellow(tag), detail)
}

// Finding holds the fields needed to display a structured finding.
type Finding struct {
	Type       string
	URL        string
	Method     string
	Parameter  string
	Payload    string
	Severity   string
	Evidence   string
	Timestamp  string
	ParamKey   string
	ParamValue string
	Position   string
	Extra      map[string]string
}

// PrintFinding displays a structured multi-line finding, Xray-style.
func PrintFinding(r Finding) {
	sev := SeverityTag(r.Severity)
	fmt.Printf("  %s %s\n", sev, r.Type)
	fmt.Printf("    %-12s %q\n", "Target", r.URL)
	if r.Method != "" {
		fmt.Printf("    %-12s %s\n", "Method", r.Method)
	}
	if r.Parameter != "" && r.Parameter != "-" {
		fmt.Printf("    %-12s %q\n", "ParamKey", r.Parameter)
	}
	if r.Payload != "" && r.Payload != "-" {
		fmt.Printf("    %-12s %q\n", "Payload", r.Payload)
	}
	if r.ParamKey != "" {
		fmt.Printf("    %-12s %q\n", "ParamKey", r.ParamKey)
	}
	if r.ParamValue != "" {
		fmt.Printf("    %-12s %q\n", "ParamValue", r.ParamValue)
	}
	if r.Position != "" {
		fmt.Printf("    %-12s %q\n", "Position", r.Position)
	}
	if r.Evidence != "" {
		fmt.Printf("    %-12s %q\n", "Evidence", r.Evidence)
	}
	if r.Timestamp != "" {
		fmt.Printf("    %-12s %s\n", "Timestamp", r.Timestamp)
	}
	if len(r.Extra) > 0 {
		for k, v := range r.Extra {
			fmt.Printf("    %-12s %q\n", k, v)
		}
	}
	fmt.Println()
}

// SeverityTag returns a colored severity label like [CRITICAL], [HIGH], etc.
func SeverityTag(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return color.BoldMagenta("[CRITICAL]")
	case "HIGH":
		return color.BoldRed("[HIGH]")
	case "MEDIUM":
		return color.BoldYellow("[MEDIUM]")
	case "LOW":
		return color.Blue("[LOW]")
	default:
		return color.Gray("[INFO]")
	}
}

// ── Module lifecycle ─────────────────────────────────────────────────────────

// ModuleStart prints a module-start banner.
func ModuleStart(name, detail string) {
	fmt.Printf("%s %s %s: %s\n", color.Cyan("[*]"), color.Gray(now()), name, detail)
}

// ModuleDone prints a module-completed line with result count.
func ModuleDone(name string, count int) {
	fmt.Printf("%s %s %s: %d finding(s)\n", color.Green("[+]"), color.Gray(now()), name, count)
}

// ── Verbose / debug ──────────────────────────────────────────────────────────

// Verbose prints a dim debug line (for --verbose mode).
func Verbose(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("    %s\n", color.Gray(msg))
}
