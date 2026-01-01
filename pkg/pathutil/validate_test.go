package pathutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantErr   bool
		errContains string
	}{
		{
			name:    "valid simple path",
			path:    "main.go",
			wantErr: false,
		},
		{
			name:    "valid absolute path",
			path:    "/tmp/test.go",
			wantErr: false,
		},
		{
			name:    "valid path with subdirectory",
			path:    "internal/domain/finding.go",
			wantErr: false,
		},
		{
			name:        "empty path",
			path:        "",
			wantErr:     true,
			errContains: "path cannot be empty",
		},
		{
			name:        "path with null bytes",
			path:        "test\x00.go",
			wantErr:     true,
			errContains: "null bytes",
		},
		{
			name:    "path with dots cleaned",
			path:    "./test/../main.go",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidatePath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestValidatePath_CleansPath(t *testing.T) {
	result, err := ValidatePath("./test/../main.go")
	require.NoError(t, err)
	assert.Equal(t, "main.go", result)
}

func TestValidatePathInDir(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		path        string
		baseDir     string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid path within directory",
			path:    filepath.Join(tmpDir, "subdir", "file.go"),
			baseDir: tmpDir,
			wantErr: false,
		},
		{
			name:    "path equals base directory",
			path:    tmpDir,
			baseDir: tmpDir,
			wantErr: false,
		},
		{
			name:        "path escapes base directory",
			path:        filepath.Join(tmpDir, "..", "escape.go"),
			baseDir:     tmpDir,
			wantErr:     true,
			errContains: "escapes base directory",
		},
		{
			name:        "empty path",
			path:        "",
			baseDir:     tmpDir,
			wantErr:     true,
			errContains: "path cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidatePathInDir(tt.path, tt.baseDir)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestValidatePath_SentinelErrors(t *testing.T) {
	_, err := ValidatePath("")
	assert.ErrorIs(t, err, ErrEmptyPath)

	_, err = ValidatePath("test\x00.go")
	assert.ErrorIs(t, err, ErrNullBytes)
}

func TestValidatePathInDir_ErrPathEscapesBase(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := ValidatePathInDir(filepath.Join(tmpDir, "..", "escape.go"), tmpDir)
	assert.ErrorIs(t, err, ErrPathEscapesBase)
}

func TestIsPathSafe(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		expect bool
	}{
		{
			name:   "simple filename",
			path:   "main.go",
			expect: true,
		},
		{
			name:   "absolute path",
			path:   "/tmp/test.go",
			expect: true,
		},
		{
			name:   "path with subdirectory",
			path:   "internal/domain/finding.go",
			expect: true,
		},
		{
			name:   "empty path",
			path:   "",
			expect: false,
		},
		{
			name:   "path with null bytes",
			path:   "test\x00.go",
			expect: false,
		},
		{
			name:   "path traversal at start",
			path:   "../../../etc/passwd",
			expect: false,
		},
		{
			name:   "relative path with dots",
			path:   "./test.go",
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPathSafe(tt.path)
			assert.Equal(t, tt.expect, result)
		})
	}
}

func TestValidatePath_ExistingPath(t *testing.T) {
	// Create a real file to test symlink resolution
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.go")
	require.NoError(t, writeTestFile(testFile))

	result, err := ValidatePath(testFile)
	require.NoError(t, err)
	assert.NotEmpty(t, result)
	// Result should be the real path (symlinks resolved)
	assert.Contains(t, result, "test.go")
}

func TestValidatePathInDir_ExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "subdir", "test.go")
	require.NoError(t, writeTestFile(testFile))

	result, err := ValidatePathInDir(testFile, tmpDir)
	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "subdir")
	assert.Contains(t, result, "test.go")
}

func TestValidatePathInDir_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentFile := filepath.Join(tmpDir, "does-not-exist.go")

	result, err := ValidatePathInDir(nonExistentFile, tmpDir)
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestValidatePathInDir_AbsolutePathResolution(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.go")
	require.NoError(t, writeTestFile(testFile))

	// Test with relative base and absolute path
	result, err := ValidatePathInDir(testFile, tmpDir)
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(result))
}

func writeTestFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("package main"), 0644)
}
