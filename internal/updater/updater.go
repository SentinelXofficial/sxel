package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/internal/version"
)

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

func Update() {
	latest, err := FetchLatest()
	if err != nil {
		output.Error("Update check failed: %v", err)
		os.Exit(1)
	}
	if latest == version.Current {
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
	if resp.StatusCode != 200 {
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
	f.Close()
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
