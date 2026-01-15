package tui

import (
	"strings"
)

// truncatePath shortens a file path to maxLen characters.
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	// Keep the last maxLen-3 characters with "..." prefix
	return "..." + path[len(path)-maxLen+3:]
}

// wrapText wraps text to fit within width characters.
func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}

	var result strings.Builder
	words := strings.Fields(text)
	lineLen := 0

	for i, word := range words {
		wordLen := len(word)

		if lineLen+wordLen+1 > width && lineLen > 0 {
			result.WriteString("\n")
			lineLen = 0
		}

		if lineLen > 0 {
			result.WriteString(" ")
			lineLen++
		}

		result.WriteString(word)
		lineLen += wordLen

		// Handle case where a single word is longer than width
		if i < len(words)-1 && lineLen >= width {
			result.WriteString("\n")
			lineLen = 0
		}
	}

	return result.String()
}

// max returns the maximum of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// clamp constrains a value to a range.
func clamp(value, minVal, maxVal int) int {
	if value < minVal {
		return minVal
	}
	if value > maxVal {
		return maxVal
	}
	return value
}

// repeat returns a string with s repeated n times.
func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(s, n)
}

// padRight pads a string to width with spaces on the right.
func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + repeat(" ", width-len(s))
}

// padLeft pads a string to width with spaces on the left.
func padLeft(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return repeat(" ", width-len(s)) + s
}

// centerText centers text in a field of width characters.
func centerText(s string, width int) string {
	if len(s) >= width {
		return s
	}
	leftPad := (width - len(s)) / 2
	rightPad := width - len(s) - leftPad
	return repeat(" ", leftPad) + s + repeat(" ", rightPad)
}
