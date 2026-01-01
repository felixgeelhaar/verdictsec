// Package pathutil provides utilities for safe path handling.
package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidatePath ensures a path is safe and doesn't escape the allowed scope.
// It returns the cleaned absolute path if valid.
// This function also resolves symlinks to detect symlink-based path traversal attacks.
// Returns ErrEmptyPath if path is empty, ErrNullBytes if path contains null bytes.
func ValidatePath(path string) (string, error) {
	if path == "" {
		return "", ErrEmptyPath
	}

	// Clean the path to resolve . and ..
	cleaned := filepath.Clean(path)

	// Check for null bytes (path traversal attack vector)
	if strings.Contains(cleaned, "\x00") {
		return "", ErrNullBytes
	}

	// Resolve symlinks to prevent symlink-based path traversal
	// Note: EvalSymlinks also cleans the path and returns absolute path if input exists
	realPath, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		// If the path doesn't exist yet, return the cleaned path
		// This allows creating new files in valid locations
		return cleaned, nil
	}

	return realPath, nil
}

// ValidatePathInDir ensures a path is within the specified directory.
// Returns the cleaned absolute path if valid.
// This function resolves symlinks in both the path and base directory
// to prevent symlink-based path traversal attacks.
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

	// Resolve symlinks in base directory to get real path
	realBase, err := filepath.EvalSymlinks(absBase)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base directory symlinks: %w", err)
	}

	// For the target path, we need to handle the case where the path doesn't exist yet.
	// We resolve symlinks on the existing parent directories to get the real path prefix.
	realPath := absPath
	if evalPath, err := filepath.EvalSymlinks(absPath); err == nil {
		// Path exists - use fully resolved path
		realPath = evalPath
	} else {
		// Path doesn't exist - resolve symlinks on existing parent directory
		// Walk up until we find an existing directory
		dir := absPath
		var nonExistentParts []string
		for {
			parent := filepath.Dir(dir)
			if parent == dir {
				// Reached root, use absPath as-is
				break
			}
			if evalDir, err := filepath.EvalSymlinks(parent); err == nil {
				// Found existing parent - reconstruct path with resolved base
				for i := len(nonExistentParts) - 1; i >= 0; i-- {
					evalDir = filepath.Join(evalDir, nonExistentParts[i])
				}
				realPath = filepath.Join(evalDir, filepath.Base(absPath))
				break
			}
			nonExistentParts = append(nonExistentParts, filepath.Base(dir))
			dir = parent
		}
	}

	// Ensure the resolved path is within the resolved base directory
	if !strings.HasPrefix(realPath, realBase+string(filepath.Separator)) && realPath != realBase {
		return "", fmt.Errorf("%w: %s", ErrPathEscapesBase, path)
	}

	return realPath, nil
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
