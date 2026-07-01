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
/____/\___/_/ /_/\__/_/_/ /_/\___/_____/_/|_|

  sxel — Web Vulnerability Scanner`)
	fmt.Printf("  Version: \033[31m%s\033[0m", version.Current)

	latest := fetchLatest()
	if latest != "" && latest != version.Current {
		fmt.Printf("  (latest: \033[32m%s\033[0m — run \033[33msxel --update\033[0m)", latest)
	}
	fmt.Println("\n")
}

func fetchLatest() string {
	client := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+version.Repo+"/releases/latest", nil)
	req.Header.Set("User-Agent", "sxel/"+version.Current)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var data struct {
		TagName string `json:"tag_name"`
	}
	json.NewDecoder(resp.Body).Decode(&data)
	return data.TagName
}
