package output

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxel/internal/color"
)

const tsFormat = "2006-01-02 15:04:05"

var outMu sync.Mutex

func now() string { return time.Now().Format(tsFormat) }

func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s\n", color.Cyan("[INFO]"), color.Gray(now()), msg)
}

func Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s\n", color.BoldYellow("[WARN]"), color.Gray(now()), msg)
}

func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s\n", color.BoldRed("[ERROR]"), color.Gray(now()), msg)
}

func Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s\n", color.Green("[+]"), color.Gray(now()), msg)
}

func Debug(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s\n", color.Gray("[DEBUG]"), color.Gray(now()), msg)
}

func Plain(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Print(msg)
}

func Status(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s\n", color.Cyan("[*]"), color.Gray(now()), msg)
}

func Separator() {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Println("────────────────────────────────────────────────────────────")
}

func Progress(scanned, pending int, sent int64, latency time.Duration, failedRatio float64, current string) {
	line := fmt.Sprintf("%s scanned: %d, pending: %d, requestSent: %d, latency: %v, failedRatio: %.1f%%",
		color.Cyan("[*]"), scanned, pending, sent, latency.Round(time.Millisecond), failedRatio)
	if current != "" {
		line += "  →  " + current
	}
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("\r\033[K%s\n", line)
}

func CrawlingURL(u string) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("\r\033[K%s %s %s\n", color.Blue("[+]"), color.Cyan("crawling:"), u)
}

func Processing(method, u string) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("\r\033[K%s %s %s %s\n", color.Green("[+]"), color.Yellow("processing"), method, u)
}

func VulnInline(vulnType string, format string, args ...interface{}) {
	detail := fmt.Sprintf(format, args...)
	tag := fmt.Sprintf("[%-6s]", vulnType)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s %s\n", color.BoldRed("[VULN]"), color.Gray(now()), color.Yellow(tag), detail)
}

func SuspectInline(vulnType string, format string, args ...interface{}) {
	detail := fmt.Sprintf(format, args...)
	tag := fmt.Sprintf("[%-6s]", vulnType)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s %s\n", color.BoldYellow("[?]"), color.Gray(now()), color.Yellow(tag), detail)
}

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

func PrintFinding(r Finding) {
	sev := SeverityTag(r.Severity)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("  %s %s\n", sev, r.Type)
	fmt.Printf("    %-12s %q\n", "Target", r.URL)
	if r.Method != "" {
		fmt.Printf("    %-12s %s\n", "Method", r.Method)
	}
	if r.Parameter != "" && r.Parameter != "-" {
		fmt.Printf("    %-12s %q\n", "Parameter", r.Parameter)
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

func ModuleStart(name, detail string) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s: %s\n", color.Cyan("[*]"), color.Gray(now()), name, detail)
}

func ModuleDone(name string, count int) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("%s %s %s: %d finding(s)\n", color.Green("[+]"), color.Gray(now()), name, count)
}

func Verbose(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf("    %s\n", color.Gray(msg))
}
