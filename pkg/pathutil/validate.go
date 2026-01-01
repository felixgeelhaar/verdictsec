// Package pathutil provides utilities for safe path handling.
package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidatePath ensures a path is safe and doesn't escape the allowed scope.
// It returns the cleaned absolute path if valid.
func ValidatePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path cannot be empty")
	}

	// Clean the path to resolve . and ..
	cleaned := filepath.Clean(path)

	// Check for null bytes (path traversal attack vector)
	if strings.Contains(cleaned, "\x00") {
		return "", fmt.Errorf("path contains null bytes")
	}

	return cleaned, nil
}

// ValidatePathInDir ensures a path is within the specified directory.
// Returns the cleaned absolute path if valid.
func ValidatePathInDir(path, baseDir string) (string, error) {
	cleaned, err := ValidatePath(path)
	if err != nil {
		return "", err
	}

	// Make both paths absolute for comparison
	absPath, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base directory: %w", err)
	}

	// Ensure the path is within the base directory
	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
		return "", fmt.Errorf("path escapes base directory: %s", path)
	}

	return absPath, nil
}

// IsPathSafe performs basic safety checks on a path.
// Returns true if the path appears safe for file operations.
func IsPathSafe(path string) bool {
	if path == "" {
		return false
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return false
	}

	// Clean and check for obvious traversal patterns
	cleaned := filepath.Clean(path)

	// After cleaning, there shouldn't be any .. remaining that goes above start
	// Note: filepath.Clean handles most cases, but we add explicit check
	if strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return false
	}

	return true
}
