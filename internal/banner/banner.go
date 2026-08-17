package banner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/internal/color"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/internal/version"
)

func normVersion(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 0 && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	return s
}

func Logo() string {
	return `
   _____            __  _            __  _  __
  / ___/___  ____  / /_(_)___  ___  / / | |/ /
  \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /  |   /
 ___/ /  __/ / / / /_/ / / / /  __/ /___/   |
/____/\___/_/ /_/\__/_/_/ /_/\___/_____/_/|_/`
}

func Print() {
	fmt.Println(Logo())
	fmt.Println()
	printVersionLine(fetchLatest())
	output.Info("sxel %s started", version.Current)
}

func PrintVersion() {
	fmt.Println(Logo())
	fmt.Println()
	printVersionLine(fetchLatest())
}

func printVersionLine(latest string) {
	versionText := version.Current
	statusText := ""
	switch {
	case latest == "":
		statusText = "  " + color.Gray("(update status unknown)")
	case normVersion(latest) == normVersion(version.Current):
		versionText = color.Green(version.Current)
		statusText = "  " + color.Green("(latest)")
	default:
		versionText = color.Red(version.Current)
		statusText = "  " + color.BoldRed(fmt.Sprintf("(outdated — latest: %s)", latest))
	}
	fmt.Println("  " + fmt.Sprintf("sxel — Web Vulnerability Scanner  %s%s", versionText, statusText))
	fmt.Println()

	if latest != "" && normVersion(latest) != normVersion(version.Current) {
		fmt.Printf("  Run: %s\n\n", color.Yellow("sxel --update"))
	}
}

func fetchLatest() string {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/"+version.Repo+"/releases/latest", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "sxel")
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
