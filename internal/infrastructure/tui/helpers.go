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
