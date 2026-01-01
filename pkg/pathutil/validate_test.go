package pathutil

import (
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
