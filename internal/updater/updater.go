package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"

	"github.com/SentinelXofficial/sxel/internal/version"
)

func FetchLatest() (string, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+version.Repo+"/releases/latest", nil)
	req.Header.Set("User-Agent", "sxel/"+version.Current)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var data struct {
		TagName string `json:"tag_name"`
	}
	json.NewDecoder(resp.Body).Decode(&data)
	return data.TagName, nil
}

func Update() {
	latest, err := FetchLatest()
	if err != nil {
		fmt.Printf("[!] Update check failed: %v\n", err)
		os.Exit(1)
	}
	if latest == version.Current {
		fmt.Printf("[+] Already on latest version: %s\n", version.Current)
		return
	}
	fmt.Printf("[*] Updating sxel to %s...\n", latest)

	asset := "sxel-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", version.Repo, latest, asset)

	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		fmt.Printf("[!] Download failed. Get it from:\n    https://github.com/%s/releases/latest\n", version.Repo)
		os.Exit(1)
	}
	defer resp.Body.Close()

	exe, _ := os.Executable()
	tmp := exe + ".new"
	f, _ := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	io.Copy(f, resp.Body)
	f.Close()
	os.Rename(tmp, exe)
	os.Chmod(exe, 0755)
	fmt.Printf("[+] Updated to %s\n", latest)
}
