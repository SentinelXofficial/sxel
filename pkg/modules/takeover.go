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

type takeoverService struct {
	Name       string
	CNAMESufx  string
	Fingerprnt string
	Markers    []string
	Severity   string
}

var takeoverServices = []takeoverService{
	{
		Name: "AWS S3", CNAMESufx: ".s3.amazonaws.com",
		Fingerprnt: "The specified bucket does not exist",
		Markers:    []string{"NoSuchBucket", "The specified bucket does not exist"},
		Severity:   "HIGH",
	},
	{
		Name: "AWS S3 (us-east-1)", CNAMESufx: ".s3-website-us-east-1.amazonaws.com",
		Fingerprnt: "The specified bucket does not exist",
		Markers:    []string{"NoSuchBucket", "The specified bucket does not exist"},
		Severity:   "HIGH",
	},
	{
		Name: "GitHub Pages", CNAMESufx: ".github.io",
		Fingerprnt: "There isn't a GitHub Pages site here",
		Markers:    []string{"There isn't a GitHub Pages site here"},
		Severity:   "HIGH",
	},
	{
		Name: "Azure Blob Storage", CNAMESufx: ".blob.core.windows.net",
		Fingerprnt: "The specified resource does not exist",
		Markers:    []string{"BlobNotFound", "The specified resource does not exist", "ResourceNotFound"},
		Severity:   "HIGH",
	},
	{
		Name: "Azure CloudApp", CNAMESufx: ".cloudapp.net",
		Fingerprnt: "The web site you are attempting to access is not available",
		Markers:    []string{"404 Web Site not found", "the web site you are attempting to access is not available"},
		Severity:   "HIGH",
	},
	{
		Name: "Azure Websites", CNAMESufx: ".azurewebsites.net",
		Fingerprnt: "404 Web Site not found",
		Markers:    []string{"404 Web Site not found", "The site you are looking for is not available"},
		Severity:   "HIGH",
	},
	{
		Name: "Heroku", CNAMESufx: ".herokuapp.com",
		Fingerprnt: "No such app",
		Markers:    []string{"No such app", "no-such-app"},
		Severity:   "HIGH",
	},
	{
		Name: "Heroku (DNS)", CNAMESufx: ".herokudns.com",
		Fingerprnt: "There's nothing here, yet",
		Markers:    []string{"There's nothing here, yet", "No such app"},
		Severity:   "HIGH",
	},
	{
		Name: "Shopify", CNAMESufx: ".myshopify.com",
		Fingerprnt: "Sorry, this shop is currently unavailable",
		Markers:    []string{"Sorry, this shop is currently unavailable", "shop is currently unavailable"},
		Severity:   "HIGH",
	},
	{
		Name: "Fastly CDN", CNAMESufx: ".fastly.net",
		Fingerprnt: "Fastly error: unknown domain",
		Markers:    []string{"Fastly error: unknown domain"},
		Severity:   "HIGH",
	},
	{
		Name: "Fastly CDN (LB)", CNAMESufx: ".fastlylb.net",
		Fingerprnt: "Fastly error: unknown domain",
		Markers:    []string{"Fastly error: unknown domain"},
		Severity:   "HIGH",
	},
	{
		Name: "AWS CloudFront", CNAMESufx: ".cloudfront.net",
		Fingerprnt: "The request could not be satisfied",
		Markers:    []string{"NoSuchBucket"},
		Severity:   "HIGH",
	},
	{
		Name: "Firebase", CNAMESufx: ".firebaseapp.com",
		Fingerprnt: "Firebase Hosting Site Not Found",
		Markers:    []string{"Firebase Hosting Site Not Found"},
		Severity:   "HIGH",
	},
	{
		Name: "Netlify", CNAMESufx: ".netlify.app",
		Fingerprnt: "Not Found - Netlify",
		Markers:    []string{"Not Found - Netlify"},
		Severity:   "HIGH",
	},
	{
		Name: "Surge.sh", CNAMESufx: ".surge.sh",
		Fingerprnt: "project not found",
		Markers:    []string{"project not found"},
		Severity:   "HIGH",
	},
	{
		Name: "ReadTheDocs", CNAMESufx: ".readthedocs.io",
		Fingerprnt: "Project not found",
		Markers:    []string{"Project not found"},
		Severity:   "MEDIUM",
	},
	{
		Name: "WPEngine", CNAMESufx: ".wpengine.com",
		Fingerprnt: "The page you were looking for doesn't exist",
		Markers:    []string{"The page you were looking for doesn't exist"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Unbounce", CNAMESufx: ".unbouncepages.com",
		Fingerprnt: "The requested URL was not found",
		Markers:    []string{"The requested URL was not found"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Tilda", CNAMESufx: ".tildacdn.com",
		Fingerprnt: "Tilda Publishing",
		Markers:    []string{"Tilda Publishing"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Pantheon", CNAMESufx: ".pantheonsite.io",
		Fingerprnt: "404 error unknown site",
		Markers:    []string{"404 error unknown site", "The requested URL was not found"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Readme.io", CNAMESufx: ".readme.io",
		Fingerprnt: "project not found",
		Markers:    []string{"project not found"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Helpjuice", CNAMESufx: ".helpjuice.com",
		Fingerprnt: "helpjuice",
		Markers:    []string{"helpjuice"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Statuspage", CNAMESufx: ".statuspage.io",
		Fingerprnt: "This page is unavailable",
		Markers:    []string{"This page is unavailable"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Bitbucket", CNAMESufx: ".bitbucket.io",
		Fingerprnt: "Repository not found",
		Markers:    []string{"Repository not found"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Intercom", CNAMESufx: ".intercom-help.com",
		Fingerprnt: "intercom",
		Markers:    []string{"intercom"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Zendesk", CNAMESufx: ".zendesk.com",
		Fingerprnt: "Help Center Closed",
		Markers:    []string{"Help Center Closed", "the help center is closed"},
		Severity:   "MEDIUM",
	},
	{
		Name: "Acquia", CNAMESufx: ".acquia-test.co",
		Fingerprnt: "acquia",
		Markers:    []string{"acquia"},
		Severity:   "LOW",
	},
	{
		Name: "Hatena Blog", CNAMESufx: ".hatenablog.com",
		Fingerprnt: "hatenablog",
		Markers:    []string{"hatenablog"},
		Severity:   "LOW",
	},
	{
		Name: "LaunchRock", CNAMESufx: ".launchrock.com",
		Fingerprnt: "launchrock",
		Markers:    []string{"launchrock"},
		Severity:   "LOW",
	},
}

func CheckSubdomainTakeover(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	var results []core.ScanResult

	host := strings.ToLower(extractHost(targetURL))
	if host == "" {
		return nil
	}

	results = append(results, checkTakeoverCNAME(client, cfg, host, targetURL)...)

	output.Info("[takeover] Checking %d common subdomains for %s...", len(builtinSubdomains), host)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 20)

	baseHost := strings.TrimPrefix(host, "www.")
	wildcard := wildcardDNS(baseHost)
	if wildcard {
		output.Info("takeover: %s resolves wildcard DNS — skipping brute-force (all CNAME lookups would be false positives)", baseHost)
	}

	for _, sub := range builtinSubdomains {
		if wildcard {
			break
		}
		candidate := sub + "." + baseHost
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			cname, err := lookupCNAME(name)
			if err != nil {
				return
			}
			for _, svc := range takeoverServices {
				if !strings.HasSuffix(strings.ToLower(cname), svc.CNAMESufx) {
					continue
				}
				mu.Lock()
				results = append(results, verifyTakeover(client, cfg, name, cname, svc)...)
				mu.Unlock()
				break
			}
		}(candidate)
	}
	wg.Wait()

	if len(results) == 0 {
		fmt.Printf("  %s\n", color.Green("[takeover] No dangling subdomains detected"))
	}
	return results
}

func checkTakeoverCNAME(client *http.Client, cfg *core.Config, host, targetURL string) []core.ScanResult {
	cname, err := lookupCNAME(host)
	if err != nil {
		return nil
	}

	for _, svc := range takeoverServices {
		if !strings.HasSuffix(strings.ToLower(cname), svc.CNAMESufx) {
			continue
		}
		return verifyTakeover(client, cfg, host, cname, svc)
	}
	return nil
}

func verifyTakeover(client *http.Client, cfg *core.Config, host, cname string, svc takeoverService) []core.ScanResult {
	answered := 0
	for _, scheme := range []string{"https://", "http://"} {
		body, status, err := core.DoGET(client, cfg, scheme+host)
		if err != nil {
			continue
		}
		answered++
		if marker := matchTakeoverMarker(body, svc); marker != "" {
			return []core.ScanResult{{
				Type:      fmt.Sprintf("Subdomain Takeover — %s", svc.Name),
				URL:       host,
				Method:    "HTTP",
				Parameter: "CNAME",
				Payload:   cname,
				Severity:  svc.Severity,
				Evidence:  fmt.Sprintf("CNAME %q → %s — HTTP %d response contains takeover marker %q", cname, svc.Name, status, marker),
				Timestamp: time.Now(),
			}}
		}
	}
	if answered > 0 {
		return []core.ScanResult{{
			Type:      fmt.Sprintf("Subdomain Takeover — %s (unconfirmed)", svc.Name),
			URL:       host,
			Method:    "HTTP",
			Parameter: "CNAME",
			Payload:   cname,
			Severity:  "INFO",
			Evidence:  fmt.Sprintf("CNAME %q → %s — HTTP(S) responses lack the provider's dangling marker; manual review required", cname, svc.Name),
			Timestamp: time.Now(),
		}}
	}
	return []core.ScanResult{{
		Type:      fmt.Sprintf("Subdomain Takeover — %s (unconfirmed)", svc.Name),
		URL:       host,
		Method:    "HTTP",
		Parameter: "CNAME",
		Payload:   cname,
		Severity:  "INFO",
		Evidence:  fmt.Sprintf("CNAME %q → %s — host did not answer HTTP(S); manual review required", cname, svc.Name),
		Timestamp: time.Now(),
	}}
}

func matchTakeoverMarker(body string, svc takeoverService) string {
	low := strings.ToLower(body)
	if svc.Fingerprnt != "" && strings.Contains(low, strings.ToLower(svc.Fingerprnt)) {
		return svc.Fingerprnt
	}
	for _, m := range svc.Markers {
		if m != "" && strings.Contains(low, strings.ToLower(m)) {
			return m
		}
	}
	return ""
}

func lookupCNAME(host string) (string, error) {
	cname, err := net.LookupCNAME(host)
	if err != nil {
		return "", err
	}
	if strings.TrimSuffix(cname, ".") == strings.TrimSuffix(host, ".") {
		return "", fmt.Errorf("no CNAME record")
	}
	return strings.TrimSuffix(cname, "."), nil
}
