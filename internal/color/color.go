package color

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

var noColor = os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb"

// Severity returns a colored string for a severity level.
func Severity(s string) string {
	if noColor {
		return s
	}
	switch s {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold).Sprint(s)
	case "HIGH":
		return color.New(color.FgHiRed).Sprint(s)
	case "MEDIUM":
		return color.New(color.FgYellow).Sprint(s)
	case "LOW":
		return color.New(color.FgBlue).Sprint(s)
	default:
		return s
	}
}

// Verdict returns a colored verdict string.
func Verdict(s string) string {
	if noColor {
		return s
	}
	switch s {
	case "ERROR":
		return color.New(color.FgRed, color.Bold).Sprint(s)
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold).Sprint(s)
	case "HIGH":
		return color.New(color.FgHiRed, color.Bold).Sprint(s)
	case "MEDIUM":
		return color.New(color.FgYellow).Sprint(s)
	case "LOW":
		return color.New(color.FgBlue).Sprint(s)
	case "OK":
		return color.New(color.FgGreen).Sprint(s)
	default:
		return s
	}
}

// Green returns a green-colored string.
func Green(s string) string {
	if noColor {
		return s
	}
	return color.New(color.FgGreen).Sprint(s)
}

// Red returns a red-colored string.
func Red(s string) string {
	if noColor {
		return s
	}
	return color.New(color.FgRed).Sprint(s)
}

// Bold returns a bold string.
func Bold(format string, args ...any) string {
	if noColor {
		return fmt.Sprintf(format, args...)
	}
	return color.New(color.Bold).Sprintf(format, args...)
}
