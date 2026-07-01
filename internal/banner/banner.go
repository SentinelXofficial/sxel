package banner
import ("fmt"
"github.com/SentinelXofficial/sxel/internal/color"
"github.com/SentinelXofficial/sxel/internal/version"
)
func Print(){
fmt.Println(`
   _____            __  _            __  _  __
  / ___/___  ____  / /_(_)___  ___  / / | |/ /
  \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /  |   /
 ___/ /  __/ / / / /_/ / / / /  __/ /___/   |
/____/\___/_/ /_/\__/_/_/ /_/\___/_____/_/|_|

  sxel — Web Vulnerability Scanner`)
fmt.Printf("  Version: "+color.RED+"%s"+color.RST+"\n\n",version.Current)
}
