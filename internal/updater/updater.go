package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/internal/version"
)

var modulePath = "github.com/" + version.Repo

var sourceClient = &http.Client{Timeout: 5 * time.Minute}

func FetchLatest() (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/"+version.Repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "sxel/"+version.Current)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}
	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("decoding GitHub response: %w", err)
	}
	return data.TagName, nil
}

func normVersion(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 0 && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	return s
}

func splitVersion(s string) (int64, string) {
	s = normVersion(s)
	var digits []byte
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' || s[i] == '.' {
			digits = append(digits, s[i])
		} else {
			return parseNum(string(digits)), s[i:]
		}
	}
	return parseNum(string(digits)), ""
}

func parseNum(digits string) int64 {
	var n int64
	for _, c := range digits {
		if c >= '0' && c <= '9' {
			n = n*10 + int64(c-'0')
		}
	}
	return n
}

func compareVersions(a, b string) int {
	na, sa := splitVersion(a)
	nb, sb := splitVersion(b)
	if na > nb {
		return 1
	}
	if na < nb {
		return -1
	}
	if sa != "" && strings.HasPrefix(sa, "-") && !strings.HasPrefix(sb, "-") {
		return -1
	}
	if sb != "" && strings.HasPrefix(sb, "-") && !strings.HasPrefix(sa, "-") {
		return 1
	}
	return 0
}

func Update() {
	latest, err := FetchLatest()
	if err != nil {
		output.Warn("Update check failed: %v — continuing with current version", err)
		return
	}
	if compareVersions(version.Current, latest) >= 0 {
		output.Success("Already on latest version: %s", version.Current)
		return
	}
	output.Info("Updating sxel to %s...", latest)

	asset := "sxel-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", version.Repo, latest, asset)

	dlClient := &http.Client{Timeout: 120 * time.Second}
	resp, err := dlClient.Get(url)
	if err != nil {
		output.Error("Download error: %v", err)
		fmt.Printf("Get the latest release from:\n    https://github.com/%s/releases/latest\n", version.Repo)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && !isFallbackError(resp.StatusCode) {
		output.Error("Download failed (HTTP %d)", resp.StatusCode)
		fmt.Printf("Get it from:\n    https://github.com/%s/releases/latest\n", version.Repo)
		os.Exit(1)
	}

	exe, err := os.Executable()
	if err != nil {
		output.Error("Cannot determine current executable path: %v", err)
		os.Exit(1)
	}
	tmp := exe + ".new"

	if resp.StatusCode != 200 {
		output.Info("Release asset not published for %s/%s, building from source...", runtime.GOOS, runtime.GOARCH)
		if err := buildFromSource(latest, tmp); err != nil {
			os.Remove(tmp)
			output.Error("Build from source failed: %v", err)
			fmt.Printf("Get the latest release from:\n    https://github.com/%s/releases/latest\n", version.Repo)
			os.Exit(1)
		}
	} else {
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			output.Error("Cannot create temp file %q: %v", tmp, err)
			os.Exit(1)
		}
		if _, err := io.Copy(f, resp.Body); err != nil {
			f.Close()
			os.Remove(tmp)
			output.Error("Download write failed: %v", err)
			os.Exit(1)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			os.Remove(tmp)
			output.Error("Flush to disk failed: %v", err)
			os.Exit(1)
		}
		if err := f.Close(); err != nil {
			os.Remove(tmp)
			output.Error("Close temp file failed: %v", err)
			os.Exit(1)
		}
		if expected := fetchChecksum(dlClient, latest, asset); expected != "" {
			if err := verifyBinary(tmp, expected); err != nil {
				os.Remove(tmp)
				output.Error("Checksum verification failed: %v — aborting update", err)
				os.Exit(1)
			}
			output.Info("Checksum verified (sha256)")
		} else {
			output.Warn("No checksum asset found for release %s — binary verified only via TLS", latest)
		}
	}

	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		output.Error("Replace binary failed: %v", err)
		os.Exit(1)
	}
	if err := os.Chmod(exe, 0755); err != nil {
		output.Error("chmod failed: %v (binary may need manual permission fix)", err)
	}
	output.Success("Updated to %s", latest)
}

func isFallbackError(respStatus int) bool {
	return respStatus == 404
}

func fetchChecksum(client *http.Client, tag, asset string) string {
	for _, n := range []string{asset + ".sha256", "checksums.txt", "SHA256SUMS"} {
		u := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", version.Repo, tag, n)
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil || resp.StatusCode != 200 {
			continue
		}
		if want := checksumFromContent(string(body), asset, n == asset+".sha256"); want != "" {
			return want
		}
	}
	return ""
}

func checksumFromContent(content, asset string, singleAllowed bool) string {
	base := path.Base(asset)
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || len(fields[0]) != 64 {
			continue
		}
		if len(fields) == 1 {
			if singleAllowed {
				return fields[0]
			}
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == asset || name == base {
			return fields[0]
		}
	}
	return ""
}

func verifyBinary(filePath, expectedHex string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, strings.TrimSpace(expectedHex)) {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", got, expectedHex)
	}
	return nil
}

func buildFromSource(tag, destPath string) error {
	url := fmt.Sprintf("https://codeload.github.com/%s/tar.gz/refs/tags/%s", version.Repo, tag)
	resp, err := sourceClient.Get(url)
	if err != nil {
		return fmt.Errorf("downloading source tarball: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("source tarball download failed (HTTP %d)", resp.StatusCode)
	}

	dir, err := os.MkdirTemp("", "sxel-source-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := extractSourceTarball(resp.Body, dir); err != nil {
		return err
	}
	if err := checkSourceTree(dir); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", destPath, "./cmd/sxel")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("go binary not found in PATH: install Go (https://go.dev/dl/) or download the release manually")
		}
		if ctx.Err() != nil {
			return errors.New("go build timed out after 10 minutes")
		}
		return fmt.Errorf("go build failed: %w\n%s", err, outputTail(out))
	}
	return nil
}

func checkSourceTree(root string) error {
	modData, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return fmt.Errorf("source tree missing go.mod: %w", err)
	}
	want := "module " + modulePath
	matched := false
	for _, line := range strings.Split(string(modData), "\n") {
		if strings.TrimSpace(line) == want {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("go.mod does not declare module %s", modulePath)
	}
	info, err := os.Stat(filepath.Join(root, "cmd", "sxel"))
	if err != nil || !info.IsDir() {
		return errors.New("source tree missing cmd/sxel directory")
	}
	return nil
}

func extractSourceTarball(r io.Reader, destDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("reading gzip stream: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar stream: %w", err)
		}
		name := stripTopLevel(hdr.Name)
		if name == "" {
			continue
		}
		target := filepath.Join(destDir, filepath.FromSlash(name))
		if !strings.HasPrefix(target, destDir+string(filepath.Separator)) {
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}

func stripTopLevel(name string) string {
	name = strings.TrimPrefix(name, "./")
	idx := strings.IndexByte(name, '/')
	if idx < 0 {
		return ""
	}
	return name[idx+1:]
}

func outputTail(out []byte) string {
	const maxTail = 4096
	if len(out) > maxTail {
		out = out[len(out)-maxTail:]
	}
	return strings.TrimSpace(string(out))
}
