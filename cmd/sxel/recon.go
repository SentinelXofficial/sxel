package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/recon"
)

func runRecon(args []string) {
	fs := flag.NewFlagSet("recon", flag.ExitOnError)
	target := fs.String("target", "", "Target domain, e.g. example.com")
	targetShort := fs.String("t", "", "Same as --target")
	active := fs.Bool("active", false, "Enable active subdomain brute-force (DNS resolution)")
	wordlistFile := fs.String("wordlist", "", "Custom subdomain wordlist file for --active")
	portsFlag := fs.String("ports", "", "Comma-separated ports to scan (default 80,443,8080,8443,8000,8888,3000,5000)")
	timeout := fs.Int("timeout", 10, "Per-request timeout (seconds)")
	concurrency := fs.Int("concurrency", 30, "Concurrent scan tasks")
	probe := fs.Bool("probe", true, "Probe open ports with HTTP requests")
	noProbe := fs.Bool("no-probe", false, "Disable HTTP probing")
	favicon := fs.Bool("favicon", false, "Compute Shodan-style favicon hashes for live hosts")
	outFile := fs.String("out", "live.txt", "Write live host list to this file")
	jsonOut := fs.String("json-output", "", "Write full recon report as JSON")
	ua := fs.String("user-agent", "Mozilla/5.0 (compatible; sxel-recon/1.0)", "User-Agent for HTTP probing")
	fs.Parse(args)

	dom := *target
	if dom == "" {
		dom = *targetShort
	}
	if dom == "" && fs.NArg() > 0 {
		dom = fs.Arg(0)
	}
	if dom == "" {
		output.Error("sxel recon requires a target: sxel recon -t example.com")
		os.Exit(2)
	}

	var ports []int
	if *portsFlag != "" {
		for _, p := range strings.Split(*portsFlag, ",") {
			n := 0
			for _, c := range strings.TrimSpace(p) {
				if c < '0' || c > '9' {
					n = -1
					break
				}
				n = n*10 + int(c-'0')
			}
			if n > 0 && n <= 65535 {
				ports = append(ports, n)
			}
		}
	}

	var words []string
	if *wordlistFile != "" {
		w, err := recon.ReadWordlistFile(*wordlistFile)
		if err != nil {
			output.Error("cannot read wordlist: %v", err)
			os.Exit(2)
		}
		words = w
		output.Info("loaded %d subdomain wordlist entries from %s", len(words), *wordlistFile)
	}

	start := time.Now()
	output.Separator()

	opts := recon.Options{
		Target:      dom,
		Active:      *active,
		Wordlist:    words,
		Ports:       ports,
		Timeout:     time.Duration(*timeout) * time.Second,
		Concurrency: *concurrency,
		UserAgent:   *ua,
		Probe:       *probe && !*noProbe,
		Favicon:     *favicon,
	}

	res, err := recon.Run(opts)
	if err != nil {
		output.Error("recon failed: %v", err)
		os.Exit(1)
	}

	output.Info("domain: %s | passive subdomains: %d | wildcard DNS: %v", res.Domain, len(res.Subdomains), res.Wildcard)
	for _, s := range res.Subdomains {
		output.Info("  subdomain: %s", s)
	}

	if len(res.Live) == 0 {
		output.Warn("no live hosts found")
	} else {
		output.Info("live hosts: %d", len(res.Live))
		for _, lh := range res.Live {
			line := fmt.Sprintf("%d  %s  [%s]", lh.Status, lh.URL, lh.Title)
			if len(lh.Tech) > 0 {
				line += "  tech=" + strings.Join(lh.Tech, ",")
			}
			if lh.Favicon != "" {
				line += "  " + lh.Favicon
			}
			output.Info("%s", line)
		}
	}

	if *outFile != "" && len(res.Live) > 0 {
		var sb strings.Builder
		for _, lh := range res.Live {
			sb.WriteString(lh.URL + "\n")
		}
		if err := os.WriteFile(*outFile, []byte(sb.String()), 0o644); err != nil {
			output.Error("cannot write %s: %v", *outFile, err)
		} else {
			output.Info("live host list written to %s (%d URLs) — ready for: sxel -l %s", *outFile, len(res.Live), *outFile)
		}
	}

	if *jsonOut != "" {
		hosts := make([]string, len(res.Subdomains))
		copy(hosts, res.Subdomains)
		sort.Strings(hosts)
		report := struct {
			Domain     string           `json:"domain"`
			Subdomains []string         `json:"subdomains"`
			Wildcard   bool             `json:"wildcard"`
			Live       []recon.LiveHost `json:"live"`
			Duration   string           `json:"duration"`
		}{
			Domain:     res.Domain,
			Subdomains: hosts,
			Wildcard:   res.Wildcard,
			Live:       res.Live,
			Duration:   time.Since(start).Round(time.Millisecond).String(),
		}
		data, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			if err := os.WriteFile(*jsonOut, data, 0o644); err != nil {
				output.Error("cannot write %s: %v", *jsonOut, err)
			} else {
				output.Info("recon report written to %s", *jsonOut)
			}
		}
	}

	output.Info("recon finished in %s", time.Since(start).Round(time.Millisecond))
}
