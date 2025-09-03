package utils

const (
	ColorReset = "\033[0m"
	ColorRed   = "\033[31m"
	ColorGreen = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue  = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan  = "\033[36m"
	ColorWhite = "\033[37m"
)

func Colorize(s, color string) string {
	return color + s + ColorReset
}

func BoldText(s string) string {
	return "\033[1m" + s + ColorReset
}

