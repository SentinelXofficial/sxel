package updater

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/internal/version"
)

// FetchLatestTemplatesVersion queries the GitHub API for the latest release tag
// of the sxel-templates repository. Returns an empty string on any error.
func FetchLatestTemplatesVersion() string {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", version.TemplatesRepo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "sxel/"+version.Current)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	return data.TagName
}

// EnsureTemplates checks whether the template directory exists and contains at
// least one .yaml / .yml file.  If not, it downloads the latest templates from
// the sxel-templates repo automatically — with a progress line so new users
// don't think the tool is stuck.
func EnsureTemplates(dir string) {
	if hasTemplates(dir) {
		return
	}

	output.Status("Preparing Engine — downloading templates...")

	if err := downloadTemplates(dir); err != nil {
		output.Warn("Could not auto-download templates: %v — run 'sxel --update-templates' manually", err)
		return
	}

	count := countTemplates(dir)
	ver := readLocalTemplateVersion(dir)
	output.Success("Engine ready — %d template(s) loaded (%s)", count, ver)
}

// UpdateTemplates downloads the latest template release tarball from GitHub and
// extracts it into dir (the --template-dir).  Called by --update-templates.
// Exits the process on failure so the CLI command can be retried.
func UpdateTemplates(dir string) {
	local := readLocalTemplateVersion(dir)

	latest := FetchLatestTemplatesVersion()
	if latest == "" {
		output.Error("Cannot fetch latest template version — check your network or the repo %s", version.TemplatesRepo)
		os.Exit(1)
	}

	if local == latest && local != "" {
		output.Success("Templates already up-to-date: %s", latest)
		return
	}

	output.Info("Updating templates %s → %s...", local, latest)

	if err := downloadTemplates(dir); err != nil {
		output.Error("%v", err)
		os.Exit(1)
	}

	count := countTemplates(dir)
	output.Success("Templates updated to %s — %d template(s) loaded", latest, count)
}

// ── internals ──────────────────────────────────────────────────────────────────

// hasTemplates returns true if dir exists and contains at least one YAML file.
func hasTemplates(dir string) bool {
	found := false
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || found {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		name := strings.ToLower(info.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			found = true
		}
		return nil
	})
	return found
}

// downloadTemplates fetches the latest release tarball and extracts it into dir.
func downloadTemplates(dir string) error {
	latest := FetchLatestTemplatesVersion()
	if latest == "" {
		return fmt.Errorf("cannot reach GitHub API for %s", version.TemplatesRepo)
	}

	tag := latest
	dlURL := fmt.Sprintf("https://github.com/%s/archive/refs/tags/%s.tar.gz", version.TemplatesRepo, tag)

	dlClient := &http.Client{Timeout: 120 * time.Second}
	resp, err := dlClient.Get(dlURL)
	if err != nil {
		return fmt.Errorf("download error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("template download failed (HTTP %d)", resp.StatusCode)
	}

	// GitHub archives unpack to sxel-templates-{tag}/ — strip that prefix
	repoName := version.TemplatesRepo[strings.LastIndex(version.TemplatesRepo, "/")+1:]
	prefix1 := repoName + "-" + strings.TrimPrefix(tag, "v") + "/"
	prefix2 := repoName + "-" + tag + "/"

	if err := extractTarGz(resp.Body, dir, prefix1, prefix2); err != nil {
		return fmt.Errorf("extract failed: %w", err)
	}

	// Write local version marker
	verFile := filepath.Join(dir, ".version")
	_ = os.WriteFile(verFile, []byte(latest+"\n"), 0644)

	// Remove the stray top-level folder that GitHub creates inside the archive
	// if extractTarGz left one behind (safety cleanup).
	cleanDir := filepath.Join(dir, repoName+"-"+strings.TrimPrefix(tag, "v"))
	if info, err := os.Stat(cleanDir); err == nil && info.IsDir() {
		_ = os.RemoveAll(cleanDir)
	}
	cleanDir2 := filepath.Join(dir, repoName+"-"+tag)
	if info, err := os.Stat(cleanDir2); err == nil && info.IsDir() {
		_ = os.RemoveAll(cleanDir2)
	}

	return nil
}

// readLocalTemplateVersion reads the .version file inside dir.
func readLocalTemplateVersion(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, ".version"))
	if err != nil {
		return "(none)"
	}
	return strings.TrimSpace(string(data))
}

// extractTarGz decompresses a gzipped tarball into dst, stripping the given
// directory prefixes from each entry's path.
func extractTarGz(r io.Reader, dst, prefix1, prefix2 string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar entry: %w", err)
		}

		// Strip the top-level directory prefix
		name := hdr.Name
		name = strings.TrimPrefix(name, prefix1)
		name = strings.TrimPrefix(name, prefix2)
		if name == "" || name == hdr.Name {
			if name == hdr.Name {
				continue
			}
			continue
		}

		target := filepath.Join(dst, name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(target, 0755)
		case tar.TypeReg:
			_ = os.MkdirAll(filepath.Dir(target), 0755)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("creating %s: %w", target, err)
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return fmt.Errorf("writing %s: %w", target, err)
			}
		}
	}
	return nil
}

// countTemplates counts YAML files (excluding .version) in the template directory.
func countTemplates(dir string) int {
	n := 0
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		name := strings.ToLower(info.Name())
		if (strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) && info.Name() != ".version" {
			n++
		}
		return nil
	})
	return n
}
