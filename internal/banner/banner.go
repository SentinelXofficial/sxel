package banner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/SentinelXofficial/sxel/internal/version"
)

func Print() {
	fmt.Println(`
   _____            __  _            __  _  __
  / ___/___  ____  / /_(_)___  ___  / / | |/ /
  \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /  |   /
 ___/ /  __/ / / / /_/ / / / /  __/ /___/   |
/____/\___/_/ /_/\__/_/_/ /_/\___/_____/_/|_/

  sxel — Web Vulnerability Scanner`)

	latest := fetchLatest()
	if latest == "" {
		fmt.Printf("  Version: \033[31m%s\033[0m\n\n", version.Current)
	} else if latest == version.Current {
		fmt.Printf("  Version: \033[31m%s\033[0m \033[32m(latest)\033[0m\n\n", version.Current)
	} else {
		fmt.Printf("  Version: \033[31m%s\033[0m \033[33m(outdated — latest: %s)\033[0m\n", version.Current, latest)
		fmt.Printf("  Run: \033[33msxel --update\033[0m\n\n")
	}
}

func fetchLatest() string {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+version.Repo+"/releases/latest", nil)
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
