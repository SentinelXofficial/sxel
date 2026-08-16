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

func UpdateTemplates(dir string) {
	local := readLocalTemplateVersion(dir)

	latest := FetchLatestTemplatesVersion()
	if latest == "" {
		output.Error("Cannot fetch latest template version — check your network or the repo %s", version.TemplatesRepo)
		os.Exit(1)
	}

	if local != "(none)" && compareVersions(local, latest) >= 0 {
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

	tmpDir, err := os.MkdirTemp(filepath.Dir(dir), ".tpl-update-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := extractTarGz(resp.Body, tmpDir); err != nil {
		return fmt.Errorf("extract failed: %w", err)
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir templates: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read templates dir: %w", err)
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if err := os.RemoveAll(p); err != nil {
				return fmt.Errorf("remove stale templates dir %s: %w", e.Name(), err)
			}
			continue
		}
		lower := strings.ToLower(e.Name())
		if lower == ".version" || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
			os.Remove(p)
		}
	}

	srcEntries, err := os.ReadDir(tmpDir)
	if err != nil {
		return fmt.Errorf("read temp templates: %w", err)
	}
	for _, e := range srcEntries {
		if err := os.Rename(filepath.Join(tmpDir, e.Name()), filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("install template %s: %w", e.Name(), err)
		}
	}

	verFile := filepath.Join(dir, ".version")
	_ = os.WriteFile(verFile, []byte(latest+"\n"), 0644)

	return nil
}

func readLocalTemplateVersion(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, ".version"))
	if err != nil {
		return "(none)"
	}
	return strings.TrimSpace(string(data))
}

func extractTarGz(r io.Reader, dst string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	extracted := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar entry: %w", err)
		}

		name := hdr.Name
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		if name == "" {
			continue
		}

		if strings.Contains(name, "..") || filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
			output.Warn("Skipping unsafe template archive entry %q", hdr.Name)
			continue
		}
		clean := filepath.Clean(name)
		if clean != name || strings.HasPrefix(clean, "..") {
			output.Warn("Skipping unsafe template archive entry %q", hdr.Name)
			continue
		}

		target := filepath.Join(dst, clean)
		dstClean := filepath.Clean(dst)
		if !strings.HasPrefix(target, dstClean+string(os.PathSeparator)) && target != dstClean {
			output.Warn("Skipping unsafe template archive entry %q", hdr.Name)
			continue
		}

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
			extracted++
		}
	}

	if extracted == 0 {
		return fmt.Errorf("archive contained no extractable files (unexpected layout?)")
	}
	return nil
}

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
