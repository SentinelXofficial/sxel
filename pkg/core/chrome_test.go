package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureChromeEnv(t *testing.T) {
	resetEnsureChrome()
	os.Setenv("SXEL_CHROME", "/bin/echo")
	defer os.Unsetenv("SXEL_CHROME")
	if p := EnsureChrome(); p != "/bin/echo" {
		t.Errorf("EnsureChrome with SXEL_CHROME = %q, want /bin/echo", p)
	}
}

func TestEnsureChromeCacheHit(t *testing.T) {
	resetEnsureChrome()
	old := fetchChromeVersionFn
	fetchChromeVersionFn = func() (string, error) { return "test-version", nil }
	defer func() { fetchChromeVersionFn = old }()
	dir := t.TempDir()
	bin := filepath.Join(dir, "headless_shell")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".version"), []byte("test-version\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Setenv("SXEL_CHROME", "none")
	defer os.Unsetenv("SXEL_CHROME")
	os.Setenv("SXEL_CHROME_DIR", dir)
	defer os.Unsetenv("SXEL_CHROME_DIR")
	if p := EnsureChrome(); p != bin {
		t.Errorf("EnsureChrome cache hit = %q, want %q", p, bin)
	}
}

func TestChromeReleaseInfoNoChrome(t *testing.T) {
	os.Setenv("SXEL_CHROME", "none")
	defer os.Unsetenv("SXEL_CHROME")
	os.Setenv("SXEL_CHROME_DIR", filepath.Join(t.TempDir(), "missing"))
	defer os.Unsetenv("SXEL_CHROME_DIR")
	if info := ChromeReleaseInfo(); info != "none (auto-downloads headless-shell on first --js-crawl)" {
		t.Errorf("ChromeReleaseInfo = %q", info)
	}
}
