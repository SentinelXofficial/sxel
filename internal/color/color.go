package color

import "github.com/fatih/color"

func Red(s string) string         { return color.RedString(s) }
func Green(s string) string       { return color.GreenString(s) }
func Yellow(s string) string      { return color.YellowString(s) }
func Blue(s string) string        { return color.BlueString(s) }
func Magenta(s string) string     { return color.MagentaString(s) }
func Cyan(s string) string        { return color.CyanString(s) }
func Gray(s string) string        { return color.HiBlackString(s) }
func Bold(s string) string        { return color.New(color.Bold).Sprint(s) }
func BoldRed(s string) string     { return color.New(color.FgRed, color.Bold).Sprint(s) }
func BoldGreen(s string) string   { return color.New(color.FgGreen, color.Bold).Sprint(s) }
func BoldMagenta(s string) string { return color.New(color.FgMagenta, color.Bold).Sprint(s) }
func BoldYellow(s string) string  { return color.New(color.FgYellow, color.Bold).Sprint(s) }
