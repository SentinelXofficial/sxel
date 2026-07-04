package engine

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"gopkg.in/yaml.v3"
)

// ── YAML Template Schema ─────────────────────────────────────────────────────

// Template represents a parsed YAML scanning template.
type Template struct {
	ID    string      `yaml:"id"`
	Brief TemplateBrief `yaml:"brief"`
	Moves []TemplateMove `yaml:"moves"`
}

// TemplateBrief holds template metadata.
type TemplateBrief struct {
	Title string   `yaml:"title"`
	By    string   `yaml:"by"`
	Level string   `yaml:"level"`
	About string   `yaml:"about"`
	Label []string `yaml:"label,omitempty"`
	Score string   `yaml:"score,omitempty"`
}

// TemplateMove is a single HTTP probe within a template.
type TemplateMove struct {
	Verb  string            `yaml:"verb"`
	To    []string          `yaml:"to"`
	Head  map[string]string `yaml:"head,omitempty"`
	Body  string            `yaml:"body,omitempty"`
	Signs []TemplateSign    `yaml:"signs"`
}

// TemplateSign is a detection condition.
type TemplateSign struct {
	On     string `yaml:"on"`               // "word" or "status"
	Has    []string `yaml:"has,omitempty"`   // keywords for word match
	In     string `yaml:"in,omitempty"`      // "body", "header", "all" (default: "body")
	Need   string `yaml:"need,omitempty"`    // "any" (default) or "all"
	Flip   bool   `yaml:"flip,omitempty"`    // invert match
	Status []int  `yaml:"status,omitempty"`  // expected status codes
}

// ── Template Loading ─────────────────────────────────────────────────────────

// LoadTemplates recursively loads all .yaml templates from a directory.
func LoadTemplates(dir string) ([]Template, error) {
	var templates []Template
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") &&
			!strings.HasSuffix(strings.ToLower(info.Name()), ".yml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		var tmpl Template
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil // skip malformed templates
		}
		if tmpl.ID == "" || len(tmpl.Moves) == 0 {
			return nil // skip invalid templates
		}
		// Default: label parsing from YAML inline string like "[a, b, c]"
		if len(tmpl.Brief.Label) == 1 && strings.Contains(tmpl.Brief.Label[0], ",") {
			raw := tmpl.Brief.Label[0]
			raw = strings.Trim(raw, "[]")
			var parts []string
			for _, p := range strings.Split(raw, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					parts = append(parts, p)
				}
			}
			if len(parts) > 0 {
				tmpl.Brief.Label = parts
			}
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, err
}

// ── Template Runner ──────────────────────────────────────────────────────────

// RunTemplates executes all loaded templates against a target URL.
// Returns scan results for any matched templates.
func RunTemplates(client *http.Client, cfg *core.Config, targetURL string, templates []Template) []core.ScanResult {
	var results []core.ScanResult
	base, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	baseURL := fmt.Sprintf("%s://%s", base.Scheme, base.Host)
	hostname := base.Host

	for _, tmpl := range templates {
		for _, move := range tmpl.Moves {
			for _, rawPath := range move.To {
				// Expand template variables
				reqURL := strings.ReplaceAll(rawPath, "{{BaseURL}}", baseURL)
				reqURL = strings.ReplaceAll(reqURL, "{{Hostname}}", hostname)

				// Substitute OOB/interactsh URL if available
				oobURL := cfg.OOBAddress
				if oobURL == "" {
					oobURL = "127.0.0.1:0" // placeholder; OOB server not active
				}
				reqURL = strings.ReplaceAll(reqURL, "{{interactsh-url}}", oobURL)
				reqURL = strings.ReplaceAll(reqURL, "{{OOB_URL}}", oobURL)

				// Substitute placeholders in body too
				reqBody := move.Body
				reqBody = strings.ReplaceAll(reqBody, "{{BaseURL}}", baseURL)
				reqBody = strings.ReplaceAll(reqBody, "{{Hostname}}", hostname)
				reqBody = strings.ReplaceAll(reqBody, "{{interactsh-url}}", oobURL)
				reqBody = strings.ReplaceAll(reqBody, "{{OOB_URL}}", oobURL)

				// Build request
				req, err := http.NewRequest(move.Verb, reqURL, strings.NewReader(reqBody))
				if err != nil {
					continue
				}
				core.ApplyHeaders(req, cfg)
				for k, v := range move.Head {
					// Substitute placeholders in header values
					hv := strings.ReplaceAll(v, "{{BaseURL}}", baseURL)
					hv = strings.ReplaceAll(hv, "{{Hostname}}", hostname)
					hv = strings.ReplaceAll(hv, "{{interactsh-url}}", oobURL)
					hv = strings.ReplaceAll(hv, "{{OOB_URL}}", oobURL)
					req.Header.Set(k, hv)
				}

				// Send
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				bodyStr := core.ReadBody(resp.Body)
				resp.Body.Close()

				// Match signs
				if matchSigns(move.Signs, bodyStr, resp) {
					sev := mapLevel(tmpl.Brief.Level)
					results = append(results, core.ScanResult{
						Type:      fmt.Sprintf("Template: %s", tmpl.Brief.Title),
						URL:       reqURL,
						Method:    move.Verb,
						Parameter: "template",
						Payload:   tmpl.ID,
						Severity:  sev,
						Evidence:  fmt.Sprintf("Template %q matched — %s", tmpl.ID, tmpl.Brief.About),
						Timestamp: time.Now(),
						Extra: map[string]string{
							"template_id":  tmpl.ID,
							"score":        tmpl.Brief.Score,
						},
					})
					output.VulnInline("TPL", "%s → %s [%s]", tmpl.ID, tmpl.Brief.Title, sev)
					break // one match per move is enough
				}
			}
		}
	}
	return results
}

// RunSingleTemplate runs a single template against a specific URL.
func RunSingleTemplate(client *http.Client, cfg *core.Config, tmpl Template, targetURL string) []core.ScanResult {
	return RunTemplates(client, cfg, targetURL, []Template{tmpl})
}

// ── Sign Matching ────────────────────────────────────────────────────────────

func matchSigns(signs []TemplateSign, body string, resp *http.Response) bool {
	if len(signs) == 0 {
		return false
	}
	for _, sign := range signs {
		if sign.On == "status" {
			if matchStatus(sign, resp) {
				return true
			}
		} else {
			// Default: word matching
			if matchWords(sign, body, resp) {
				return true
			}
		}
	}
	return false
}

func matchStatus(sign TemplateSign, resp *http.Response) bool {
	if len(sign.Status) == 0 {
		return false
	}
	for _, expected := range sign.Status {
		if resp.StatusCode == expected {
			return !sign.Flip
		}
	}
	return sign.Flip
}

func matchWords(sign TemplateSign, body string, resp *http.Response) bool {
	if len(sign.Has) == 0 {
		return false
	}

	scope := sign.In
	if scope == "" {
		scope = "body"
	}

	need := sign.Need
	if need == "" {
		need = "any"
	}

	// Build search corpus
	var corpus string
	switch scope {
	case "body":
		corpus = strings.ToLower(body)
	case "header":
		corpus = flattenHeaders(resp)
	case "all":
		corpus = strings.ToLower(body) + " " + flattenHeaders(resp)
	}

	matched := 0
	for _, keyword := range sign.Has {
		if strings.Contains(corpus, strings.ToLower(keyword)) {
			matched++
			if need == "any" {
				return !sign.Flip
			}
		}
	}

	if need == "all" {
		return (matched == len(sign.Has)) != sign.Flip
	}
	return sign.Flip
}

func flattenHeaders(resp *http.Response) string {
	var parts []string
	for k, vals := range resp.Header {
		for _, v := range vals {
			parts = append(parts, strings.ToLower(k)+": "+strings.ToLower(v))
		}
	}
	return strings.Join(parts, " ")
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func mapLevel(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return "INFO"
	}
}

// vendorLabels maps template label tags to the technology that must be
// detected for the template to run. Labels NOT in this map are considered
// generic (always run).
var vendorLabels = map[string]string{
	"wordpress":      "WordPress",
	"joomla":         "Joomla",
	"drupal":         "Drupal",
	"magento":        "Magento",
	"laravel":        "Laravel",
	"django":         "Django",
	"ruby-on-rails":  "Ruby on Rails",
	"rails":          "Ruby on Rails",
	"spring":         "Spring Boot",
	"spring-boot":    "Spring Boot",
	"struts":         "Apache Struts",
	"tomcat":         "Tomcat",
	"apache":         "Apache",
	"nginx":          "Nginx",
	"iis":            "IIS",
	"node.js":        "Node.js",
	"express":        "Express.js",
	"next.js":        "Next.js",
	"react":          "React",
	"angular":        "Angular",
	"vue":            "Vue.js",
	"flask":          "Flask",
	"fastapi":        "FastAPI",
	"grafana":        "Grafana",
	"jenkins":        "Jenkins",
	"gitlab":         "GitLab",
	"github":         "GitHub",
	"weblogic":       "Oracle WebLogic",
	"websphere":      "IBM WebSphere",
	"jboss":          "JBoss",
	"wildfly":        "WildFly",
	"phpmyadmin":     "phpMyAdmin",
	"cpanel":         "cPanel",
	"plesk":          "Plesk",
	"solr":           "Apache Solr",
	"elastic":        "Elasticsearch",
	"kibana":         "Kibana",
	"logstash":       "Logstash",
	"splunk":         "Splunk",
	"prometheus":     "Prometheus",
	"kubernetes":     "Kubernetes",
	"docker":         "Docker",
	"ansible":        "Ansible",
	"terraform":      "Terraform",
	"confluence":     "Atlassian Confluence",
	"jira":           "Atlassian Jira",
	"bitbucket":      "Atlassian Bitbucket",
	"vsphere":        "VMware vSphere",
	"vmware":         "VMware",
	"citrix":         "Citrix",
	"cisco":          "Cisco",
	"fortinet":       "Fortinet",
	"fortigate":      "Fortinet",
	"paloalto":       "Palo Alto",
	"f5":             "F5",
	"bigip":          "F5 BIG-IP",
	"haproxy":        "HAProxy",
	"varnish":        "Varnish",
	"squid":          "Squid",
	"kong":           "Kong",
	"zabbix":         "Zabbix",
	"nagios":         "Nagios",
	"oracle":         "Oracle",
	"sap":            "SAP",
	"salesforce":     "Salesforce",
	"sharepoint":     "SharePoint",
	"moodle":         "Moodle",
	"prestashop":     "PrestaShop",
	"shopify":        "Shopify",
	"typo3":          "TYPO3",
	"umbraco":        "Umbraco",
	"sitecore":       "Sitecore",
	"squirrelmail":   "SquirrelMail",
	"roundcube":      "Roundcube",
	"zimbra":         "Zimbra",
	"exchange":       "Microsoft Exchange",
	"coldfusion":     "Adobe ColdFusion",
	"php":            "PHP",
	"java":           "Java",
	"asp.net":        "ASP.NET",
	"dotnet":         ".NET",
	"python":         "Python",
	"go":             "Go",
	"ruby":           "Ruby",
}

// FilterTemplatesByTech returns only templates relevant to the detected
// technology stack. Templates with no vendor-specific labels always pass.
func FilterTemplatesByTech(templates []Template, detectedTech []string) []Template {
	if len(detectedTech) == 0 {
		// No tech detected — only run templates without vendor-specific labels
		return filterGeneric(templates)
	}

	techSet := make(map[string]bool, len(detectedTech))
	for _, t := range detectedTech {
		techSet[strings.ToLower(t)] = true
	}

	var filtered []Template
	for _, tmpl := range templates {
		requiredVendor := ""
		for _, label := range tmpl.Brief.Label {
			if vendor, ok := vendorLabels[strings.ToLower(label)]; ok {
				requiredVendor = vendor
				break
			}
		}

		if requiredVendor == "" {
			// No vendor requirement — generic template, always run
			filtered = append(filtered, tmpl)
		} else if techSet[strings.ToLower(requiredVendor)] {
			// Vendor matches detected tech
			filtered = append(filtered, tmpl)
		}
		// else: vendor-specific template but vendor not detected → skip
	}
	return filtered
}

// filterGeneric returns templates that have no vendor/tech-specific labels.
func filterGeneric(templates []Template) []Template {
	var filtered []Template
	for _, tmpl := range templates {
		hasVendor := false
		for _, label := range tmpl.Brief.Label {
			if _, ok := vendorLabels[strings.ToLower(label)]; ok {
				hasVendor = true
				break
			}
		}
		if !hasVendor {
			filtered = append(filtered, tmpl)
		}
	}
	return filtered
}

// LoadTemplateVersion reads the .version file inside the template directory.
// Returns the version string (e.g. "v0.1.0") or an empty string if not found.
func LoadTemplateVersion(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, ".version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
