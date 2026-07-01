package color

const RST = "\033[0m"

const (
	RED     = "\033[31m"
	GREEN   = "\033[32m"
	YELLOW  = "\033[33m"
	BLUE    = "\033[34m"
	MAGENTA = "\033[35m"
	CYAN    = "\033[36m"
	GRAY    = "\033[90m"
	BOLD    = "\033[1m"
)

// Wrapper functions — callers write color.Red("text") instead of
// "\033[31m" + "text" + "\033[0m".
func Red(s string) string          { return RED + s + RST }
func Green(s string) string        { return GREEN + s + RST }
func Yellow(s string) string       { return YELLOW + s + RST }
func Blue(s string) string         { return BLUE + s + RST }
func Magenta(s string) string      { return MAGENTA + s + RST }
func Cyan(s string) string         { return CYAN + s + RST }
func Gray(s string) string         { return GRAY + s + RST }
func Bold(s string) string         { return BOLD + s + RST }
func BoldRed(s string) string      { return BOLD + RED + s + RST }
func BoldMagenta(s string) string  { return BOLD + MAGENTA + s + RST }
func BoldYellow(s string) string   { return BOLD + YELLOW + s + RST }
