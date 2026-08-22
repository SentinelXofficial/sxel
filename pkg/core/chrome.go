package core

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

const (
	chromeReleaseURL = "https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_STABLE"
	chromeDownloadF  = "https://storage.googleapis.com/chrome-for-testing-public/%s/linux64/chrome-headless-shell-linux64.zip"
	chromeMaxZip     = 300 << 20
)

func ChromePath() string {
	if p := os.Getenv("SXEL_CHROME"); p != "" {
		if strings.EqualFold(p, "none") || strings.EqualFold(p, "off") {
			return ""
		}
		return p
	}
	for _, c := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "headless_shell", "msedge"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

func chromeCacheDir() string {
	if d := os.Getenv("SXEL_CHROME_DIR"); d != "" {
		return d
	}
	if base, err := os.UserCacheDir(); err == nil {
		return filepath.Join(base, "sxel", "chrome")
	}
	return filepath.Join(os.TempDir(), "sxel-chrome")
}

func fetchChromeVersion() (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(chromeReleaseURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", chromeReleaseURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(body))
	if version == "" {
		return "", fmt.Errorf("empty version from %s", chromeReleaseURL)
	}
	return version, nil
}

func downloadHeadlessShell(version string, tmpZip string) error {
	url := fmt.Sprintf(chromeDownloadF, version)
	client := &http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	out, err := os.Create(tmpZip)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(resp.Body, chromeMaxZip))
	if err != nil {
		return err
	}
	if n >= chromeMaxZip {
		return fmt.Errorf("download too large (>%d bytes)", chromeMaxZip)
	}
	return nil
}

func extractHeadlessShell(tmpZip, destDir string) (string, error) {
	zr, err := zip.OpenReader(tmpZip)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	entryName := ""
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() && (filepath.Base(f.Name) == "headless_shell" || filepath.Base(f.Name) == "chrome-headless-shell") {
			entryName = f.Name
			break
		}
	}
	if entryName == "" {
		return "", fmt.Errorf("no headless_shell binary in %s", tmpZip)
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	target := filepath.Join(destDir, "headless_shell")
	tmpBin := target + ".tmp"
	rc, err := zr.Open(entryName)
	if err != nil {
		return "", err
	}
	out, err := os.OpenFile(tmpBin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		rc.Close()
		return "", err
	}
	_, err = io.Copy(out, rc)
	rc.Close()
	out.Close()
	if err != nil {
		return "", err
	}
	if err := os.Rename(tmpBin, target); err != nil {
		return "", err
	}
	return target, nil
}

var (
	chromeMu          sync.Mutex
	ensuredChromePath string
	ensuredChromeOnce sync.Once
)

func EnsureChrome() string {
	ensuredChromeOnce.Do(func() {
		ensuredChromePath = ensureChromeOnce()
	})
	return ensuredChromePath
}

func resetEnsureChrome() {
	chromeMu.Lock()
	defer chromeMu.Unlock()
	ensuredChromeOnce = sync.Once{}
	ensuredChromePath = ""
}

func cacheChromeVersion(cache, version string) {
	_ = os.WriteFile(filepath.Join(cache, ".version"), []byte(version+"\n"), 0o644)
}

func readCachedChromeVersion(cache string) string {
	data, err := os.ReadFile(filepath.Join(cache, ".version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

var fetchChromeVersionFn = fetchChromeVersion

func ensureChromeOnce() string {
	if p := ChromePath(); p != "" {
		return p
	}
	cache := chromeCacheDir()
	bin := filepath.Join(cache, "headless_shell")
	version, err := fetchChromeVersionFn()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] js-crawl: could not fetch Chrome version: %v\n", err)
		if _, serr := os.Stat(bin); serr == nil {
			return bin
		}
		return ""
	}
	if _, err := os.Stat(bin); err == nil && readCachedChromeVersion(cache) == version {
		return bin
	}
	tmpf, err := os.CreateTemp("", "sxel-headless-shell-*.zip")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] js-crawl: temp file: %v\n", err)
		return ""
	}
	tmpZip := tmpf.Name()
	tmpf.Close()
	defer os.Remove(tmpZip)
	if err := downloadHeadlessShell(version, tmpZip); err != nil {
		fmt.Fprintf(os.Stderr, "[!] js-crawl: download headless-shell %s failed: %v\n", version, err)
		return ""
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[!] js-crawl: mkdir %s: %v\n", cache, err)
		return ""
	}
	bin, err = extractHeadlessShell(tmpZip, cache)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] js-crawl: extract headless-shell failed: %v\n", err)
		return ""
	}
	cacheChromeVersion(cache, version)
	fmt.Fprintf(os.Stderr, "[+] js-crawl: headless-shell %s ready at %s\n", version, bin)
	return bin
}

func NewDOMAllocator(chrome string) (context.Context, context.CancelFunc) {
	actx, acancel := chromedp.NewExecAllocator(context.Background(),
		chromedp.ExecPath(chrome),
		chromedp.Headless,
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("no-first-run", true),
	)
	return actx, acancel
}

func ChromeReleaseInfo() string {
	if p := ChromePath(); p != "" {
		return "system: " + p
	}
	cache := chromeCacheDir()
	bin := filepath.Join(cache, "headless_shell")
	if _, err := os.Stat(bin); err == nil {
		return "cached: " + bin
	}
	return "none (auto-downloads headless-shell on first --js-crawl)"
}
