package modules

import (
	"fmt"
	"github.com/SentinelXofficial/sxel/internal/color"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/core"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// takeoverService describes a cloud service with a known dangling-record behaviour.
type takeoverService struct {
	Name       string
	CNAMESufx  string   // CNAME suffixes indicating this service
	NXDomain   bool     // true: dangling CNAME → NXDOMAIN response
	Fingerprnt string   // HTTP response fingerprint when the record is dangling
	Markers    []string // body markers for the takeover landing page
	Severity   string
}

var takeoverServices = []takeoverService{
	{
		Name: "AWS S3", CNAMESufx: ".s3.amazonaws.com", NXDomain: true,
		Fingerprnt: "The specified bucket does not exist",
		Markers:    []string{"NoSuchBucket", "The specified bucket does not exist", "does not exist"},
		Severity:   "HIGH",
	},
	{
		Name: "AWS S3 (us-east-1)", CNAMESufx: ".s3-website-us-east-1.amazonaws.com", NXDomain: true,
		Markers:  []string{"NoSuchBucket"},
		Severity: "HIGH",
	},
	{
		Name: "GitHub Pages", CNAMESufx: ".github.io", NXDomain: true,
		Fingerprnt: "There isn't a GitHub Pages site here",
		Markers:    []string{"There isn't a GitHub Pages site here", "site here"},
		Severity:   "HIGH",
	},
	{
		Name: "Azure Blob Storage", CNAMESufx: ".blob.core.windows.net", NXDomain: true,
		Fingerprnt: "The specified resource does not exist",
		Markers:    []string{"BlobNotFound", "The specified resource does not exist", "ResourceNotFound"},
		Severity:   "HIGH",
	},
	{
		Name: "Azure CloudApp", CNAMESufx: ".cloudapp.net", NXDomain: true,
		Markers:  []string{},
		Severity: "HIGH",
	},
	{
		Name: "Azure Websites", CNAMESufx: ".azurewebsites.net", NXDomain: true,
		Markers:  []string{},
		Severity: "HIGH",
	},
	{
		Name: "Heroku", CNAMESufx: ".herokuapp.com", NXDomain: true,
		Fingerprnt: "No such app",
		Markers:    []string{"No such app", "no-such-app"},
		Severity:   "HIGH",
	},
	{
		Name: "Shopify", CNAMESufx: ".myshopify.com", NXDomain: true,
		Markers:  []string{"Sorry, this shop is currently unavailable"},
		Severity: "HIGH",
	},
	{
		Name: "Fastly CDN", CNAMESufx: ".fastly.net", NXDomain: true,
		Markers:  []string{"Fastly error: unknown domain"},
		Severity: "HIGH",
	},
	{
		Name: "Firebase", CNAMESufx: ".firebaseapp.com", NXDomain: true,
		Markers:  []string{},
		Severity: "HIGH",
	},
	{
		Name: "Netlify", CNAMESufx: ".netlify.app", NXDomain: true,
		Markers:  []string{"Not Found - Netlify"},
		Severity: "HIGH",
	},
	{
		Name: "Surge.sh", CNAMESufx: ".surge.sh", NXDomain: true,
		Markers:  []string{"project not found"},
		Severity: "HIGH",
	},
	{
		Name: "Unbounce", CNAMESufx: ".unbouncepages.com", NXDomain: true,
		Markers:  []string{},
		Severity: "MEDIUM",
	},
	{
		Name: "Tilda", CNAMESufx: ".tildacdn.com", NXDomain: true,
		Markers:  []string{},
		Severity: "MEDIUM",
	},
	{
		Name: "Pantheon", CNAMESufx: ".pantheonsite.io", NXDomain: true,
		Markers:  []string{},
		Severity: "MEDIUM",
	},
	{
		Name: "Readme.io", CNAMESufx: ".readme.io", NXDomain: true,
		Markers:  []string{"project not found"},
		Severity: "MEDIUM",
	},
	{
		Name: "Helpjuice", CNAMESufx: ".helpjuice.com", NXDomain: true,
		Markers:  []string{},
		Severity: "MEDIUM",
	},
	{
		Name: "Statuspage", CNAMESufx: ".statuspage.io", NXDomain: true,
		Markers:  []string{},
		Severity: "MEDIUM",
	},
	{
		Name: "Bitbucket", CNAMESufx: ".bitbucket.io", NXDomain: true,
		Markers:  []string{"Repository not found"},
		Severity: "MEDIUM",
	},
	{
		Name: "Intercom", CNAMESufx: ".intercom-help.com", NXDomain: true,
		Markers:  []string{},
		Severity: "MEDIUM",
	},
	{
		Name: "Zendesk", CNAMESufx: ".zendesk.com", NXDomain: true,
		Markers:  []string{"Help Center Closed"},
		Severity: "MEDIUM",
	},
	{
		Name: "Acquia", CNAMESufx: ".acquia-test.co", NXDomain: true,
		Markers:  []string{},
		Severity: "LOW",
	},
	{
		Name: "Hatena Blog", CNAMESufx: ".hatenablog.com", NXDomain: true,
		Markers:  []string{},
		Severity: "LOW",
	},
	{
		Name: "LaunchRock", CNAMESufx: ".launchrock.com", NXDomain: true,
		Markers:  []string{},
		Severity: "LOW",
	},
}

// CheckSubdomainTakeover checks if the target domain or any discovered CNAME
// points to a service that allows subdomain takeover.
func CheckSubdomainTakeover(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult

	host := extractHost(targetURL)
	if host == "" {
		return nil
	}

	// ── 1. Check the target host directly ──────────────────────────────────
	results = append(results, checkTakeoverCNAME(host, targetURL)...)

	// ── 2. Check built-in subdomain list ───────────────────────────────────
	output.Info("[takeover] Checking %d common subdomains for %s...", len(builtinSubdomains), host)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 20)

	for _, sub := range builtinSubdomains {
		candidate := sub + "." + host
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			cname, err := lookupCNAME(name)
			if err != nil {
				return // subdomain doesn't exist, skip
			}
			// Check if CNAME points to a known service
			for _, svc := range takeoverServices {
				if !strings.HasSuffix(strings.ToLower(cname), svc.CNAMESufx) {
					continue
				}
				// Check if it's dangling
				if svc.NXDomain {
					// Resolve the CNAME target — if NXDOMAIN, it's dangling
					if _, err := net.LookupHost(cname); err == nil {
						continue // still resolves, not vulnerable
					}
				}

				mu.Lock()
				results = append(results, core.ScanResult{
					Type:      fmt.Sprintf("Subdomain Takeover — %s", svc.Name),
					URL:       name,
					Method:    "DNS",
					Parameter: "CNAME",
					Payload:   cname,
					Severity:  svc.Severity,
					Evidence:  fmt.Sprintf("%s CNAME %q → %s — dangling record, takeover possible", name, cname, svc.Name),
					Timestamp: time.Now(),
				})
				mu.Unlock()
			}
		}(candidate)
	}
	wg.Wait()

	if len(results) == 0 {
		fmt.Printf("  %s\n", color.Green("[takeover] No dangling subdomains detected"))
	}
	return results
}

// checkTakeoverCNAME looks up the CNAME for a single host and checks it against
// the takeover services database.
func checkTakeoverCNAME(host, targetURL string) []core.ScanResult {
	cname, err := lookupCNAME(host)
	if err != nil {
		return nil
	}

	for _, svc := range takeoverServices {
		if !strings.HasSuffix(strings.ToLower(cname), svc.CNAMESufx) {
			continue
		}
		if svc.NXDomain {
			if _, err := net.LookupHost(cname); err == nil {
				continue
			}
		}
		return []core.ScanResult{{
			Type:      fmt.Sprintf("Subdomain Takeover — %s", svc.Name),
			URL:       targetURL,
			Method:    "DNS",
			Parameter: "CNAME",
			Payload:   cname,
			Severity:  svc.Severity,
			Evidence:  fmt.Sprintf("CNAME %q → %s — dangling record, takeover possible", cname, svc.Name),
			Timestamp: time.Now(),
		}}
	}
	return nil
}

// lookupCNAME returns the canonical name for a host, or an error.
func lookupCNAME(host string) (string, error) {
	cname, err := net.LookupCNAME(host)
	if err != nil {
		return "", err
	}
	// net.LookupCNAME returns the input unchanged if no CNAME exists
	if strings.TrimSuffix(cname, ".") == strings.TrimSuffix(host, ".") {
		return "", fmt.Errorf("no CNAME record")
	}
	return strings.TrimSuffix(cname, "."), nil
}
