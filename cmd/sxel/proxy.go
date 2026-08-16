package main

import (
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/SentinelXofficial/sxel/internal/banner"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/pkg/modules"
	"github.com/SentinelXofficial/sxel/pkg/proxy"
)

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:7777", "listen address for the proxy")
	caDir := fs.String("ca-dir", "", "directory for MITM CA (default ~/.sxel/ca)")
	reportJSON := fs.String("json-output", "", "save JSON report")
	reportHTML := fs.String("html-output", "", "save HTML report")
	scope := fs.String("scope", "", "comma-separated host suffixes to analyze (default all)")
	fs.Parse(args)

	if *caDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			output.Error("home dir: %v", err)
			return
		}
		*caDir = filepath.Join(home, ".sxel", "ca")
	}
	var scopeList []string
	if *scope != "" {
		for _, s := range strings.Split(*scope, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				scopeList = append(scopeList, s)
			}
		}
	}
	banner.Print()
	mitm, err := proxy.NewMITM(*caDir, scopeList)
	if err != nil {
		output.Error("proxy init: %v", err)
		return
	}
	caPath := filepath.Join(*caDir, "ca.pem")
	output.Info("Proxy CA: %s", caPath)
	output.Info("Trust this CA in your browser/system to scan HTTPS (MITM).")
	output.Info("Passive proxy listening on %s — configure browser/system proxy to this address.", *listen)
	output.Info("No extra requests are sent to targets: analysis is passive-only.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		if err := mitm.ListenAndServe(*listen); err != nil && err != http.ErrServerClosed {
			output.Error("proxy: %v", err)
		}
		close(done)
	}()
	select {
	case <-sig:
		output.Info("Stopping proxy...")
	case <-done:
	}
	results := mitm.Findings()
	output.Success("%s", mitm.Summary())
	if len(results) > 0 {
		for i := range results {
			results[i] = modules.EscalateSeverity(results[i])
		}
		if *reportHTML != "" {
			writeHTMLReport(*reportHTML, results)
		}
		if *reportJSON != "" {
			writeJSONReport(*reportJSON, results)
		}
	} else {
		output.Info("No findings recorded.")
	}
}
