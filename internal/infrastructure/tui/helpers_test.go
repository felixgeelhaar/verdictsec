package tui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncatePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		maxLen   int
		expected string
	}{
		{
			name:     "short path unchanged",
			path:     "main.go",
			maxLen:   20,
			expected: "main.go",
		},
		{
			name:     "long path truncated",
			path:     "very/long/path/to/some/file.go",
			maxLen:   20,
			expected: "...ath/to/some/file.go",
		},
		{
			name:     "exact length unchanged",
			path:     "exactly20characters!",
			maxLen:   20,
			expected: "exactly20characters!",
		},
		{
			name:     "one over truncated",
			path:     "exactly21characters!!",
			maxLen:   20,
			expected: "...actly21characters!!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncatePath(tt.path, tt.maxLen)
			if len(tt.path) <= tt.maxLen {
				assert.Equal(t, tt.expected, result)
			} else {
				assert.LessOrEqual(t, len(result), tt.maxLen+3) // Account for "..."
			}
		})
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		width    int
		contains []string
	}{
		{
			name:     "short text unchanged",
			text:     "hello world",
			width:    50,
			contains: []string{"hello world"},
		},
		{
			name:     "text wraps at width",
			text:     "hello world this is a long sentence",
			width:    12,
			contains: []string{"hello", "world", "this"},
		},
		{
			name:     "empty text",
			text:     "",
			width:    20,
			contains: []string{""},
		},
		{
			name:     "zero width returns original",
			text:     "hello world",
			width:    0,
			contains: []string{"hello world"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapText(tt.text, tt.width)
			for _, expected := range tt.contains {
				assert.Contains(t, result, expected)
			}
		})
	}
}
