package banner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/SentinelXofficial/sxel/internal/color"
	"github.com/SentinelXofficial/sxel/internal/output"
	"github.com/SentinelXofficial/sxel/internal/version"
)

func Print() {
	fmt.Println(`
   _____            __  _            __  _  __
  / ___/___  ____  / /_(_)___  ___  / / | |/ /
  \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /  |   /
 ___/ /  __/ / / / /_/ / / / /  __/ /___/   |
/____/\___/_/ /_/\__/_/_/ /_/\___/_____/_/|_/`)
	fmt.Println()

	latest := fetchLatest()
	versionLine := fmt.Sprintf("sxel — Web Vulnerability Scanner  %s", color.Red(version.Current))
	if latest == "" {
		versionLine += ""
	} else if latest == version.Current {
		versionLine += "  " + color.Green("(latest)")
	} else {
		versionLine += "  " + color.BoldYellow(fmt.Sprintf("(outdated — latest: %s)", latest))
	}
	fmt.Println("  " + versionLine)
	fmt.Println()

	if latest != "" && latest != version.Current {
		fmt.Printf("  Run: %s\n\n", color.Yellow("sxel --update"))
	}

	output.Info("sxel %s started", version.Current)
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
