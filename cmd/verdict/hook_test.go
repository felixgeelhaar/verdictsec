package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainsMarker(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "empty string",
			content:  "",
			expected: false,
		},
		{
			name:     "contains marker at start",
			content:  "# VerdictSec pre-commit hook\nrest of script",
			expected: true,
		},
		{
			name:     "marker only",
			content:  "# VerdictSec pre-commit hook",
			expected: true,
		},
		{
			name:     "different content",
			content:  "#!/bin/bash\necho hello",
			expected: false,
		},
		{
			name:     "marker not at start",
			content:  "something else\n# VerdictSec pre-commit hook",
			expected: false,
		},
		{
			name:     "partial marker",
			content:  "# VerdictSec",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsMarker(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateHookScript(t *testing.T) {
	// Save original values
	oldHookEngines := hookEngines
	oldHookStrict := hookStrict
	defer func() {
		hookEngines = oldHookEngines
		hookStrict = oldHookStrict
	}()

	t.Run("default engines", func(t *testing.T) {
		hookEngines = []string{"gosec", "gitleaks"}
		hookStrict = false

		script := generateHookScript()

		assert.Contains(t, script, hookMarker)
		assert.Contains(t, script, "--include=gosec,gitleaks")
		assert.NotContains(t, script, "--strict")
		assert.Contains(t, script, "verdict scan")
		assert.Contains(t, script, "set -e")
	})

	t.Run("single engine", func(t *testing.T) {
		hookEngines = []string{"gosec"}
		hookStrict = false

		script := generateHookScript()

		assert.Contains(t, script, "--include=gosec")
		assert.NotContains(t, script, ",gitleaks")
	})

	t.Run("strict mode", func(t *testing.T) {
		hookEngines = []string{"gosec"}
		hookStrict = true

		script := generateHookScript()

		assert.Contains(t, script, "--strict")
	})

	t.Run("no engines", func(t *testing.T) {
		hookEngines = []string{}
		hookStrict = false

		script := generateHookScript()

		assert.Contains(t, script, "verdict scan")
		assert.NotContains(t, script, "--include=")
	})

	t.Run("script structure", func(t *testing.T) {
		hookEngines = []string{"gosec"}
		hookStrict = false

		script := generateHookScript()

		// Verify script structure
		assert.Contains(t, script, "Running VerdictSec security scan")
		assert.Contains(t, script, "exit_code=$?")
		assert.Contains(t, script, "if [ $exit_code -ne 0 ]")
		assert.Contains(t, script, "Security issues detected")
		assert.Contains(t, script, "Security scan passed")
		assert.Contains(t, script, "exit 0")
		assert.Contains(t, script, "exit 1")
	})
}

func TestFindGitDir(t *testing.T) {
	// Create a temporary directory structure
	tmpDir, err := os.MkdirTemp("", "hook-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Resolve symlinks (macOS has /var -> /private/var)
	tmpDir, err = filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	// Create a .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	err = os.Mkdir(gitDir, 0755)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Change to tmp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Test findGitDir
	foundDir, err := findGitDir()
	require.NoError(t, err)
	assert.Equal(t, gitDir, foundDir)
}

func TestFindGitDir_InSubdirectory(t *testing.T) {
	// Create a temporary directory structure
	tmpDir, err := os.MkdirTemp("", "hook-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Resolve symlinks (macOS has /var -> /private/var)
	tmpDir, err = filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	// Create a .git directory at root
	gitDir := filepath.Join(tmpDir, ".git")
	err = os.Mkdir(gitDir, 0755)
	require.NoError(t, err)

	// Create a subdirectory
	subDir := filepath.Join(tmpDir, "src", "pkg")
	err = os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Change to subdirectory
	err = os.Chdir(subDir)
	require.NoError(t, err)

	// Test findGitDir from subdirectory
	foundDir, err := findGitDir()
	require.NoError(t, err)
	assert.Equal(t, gitDir, foundDir)
}

func TestFindGitDir_NotARepo(t *testing.T) {
	// Create a temporary directory without .git
	tmpDir, err := os.MkdirTemp("", "hook-test-no-git")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Change to tmp directory (no .git)
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Test findGitDir - should fail
	_, err = findGitDir()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a git repository")
}

func TestHookCmd_Init(t *testing.T) {
	// Verify hook commands are properly initialized
	assert.NotNil(t, hookCmd)
	assert.Equal(t, "hook", hookCmd.Use)

	assert.NotNil(t, hookInstallCmd)
	assert.Equal(t, "install", hookInstallCmd.Use)

	assert.NotNil(t, hookUninstallCmd)
	assert.Equal(t, "uninstall", hookUninstallCmd.Use)

	assert.NotNil(t, hookStatusCmd)
	assert.Equal(t, "status", hookStatusCmd.Use)
}

func TestHookInstallCmd_Flags(t *testing.T) {
	flags := hookInstallCmd.Flags()
	require.NotNil(t, flags)

	forceFlag := flags.Lookup("force")
	assert.NotNil(t, forceFlag)
	assert.Equal(t, "f", forceFlag.Shorthand)

	enginesFlag := flags.Lookup("engines")
	assert.NotNil(t, enginesFlag)

	strictFlag := flags.Lookup("strict")
	assert.NotNil(t, strictFlag)
}

func TestHookMarker(t *testing.T) {
	assert.Equal(t, "# VerdictSec pre-commit hook", hookMarker)
}

func TestRunHookInstall_NewRepo(t *testing.T) {
	// Create a temporary directory with .git
	tmpDir, err := os.MkdirTemp("", "hook-install-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	err = os.Mkdir(gitDir, 0755)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Save original values
	oldHookEngines := hookEngines
	oldHookStrict := hookStrict
	oldNoColor := noColor
	defer func() {
		hookEngines = oldHookEngines
		hookStrict = oldHookStrict
		noColor = oldNoColor
	}()

	// Set test values
	hookEngines = []string{"gosec"}
	hookStrict = false
	noColor = true

	// Change to tmp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Run install
	err = runHookInstall(nil, nil)
	require.NoError(t, err)

	// Verify hook was created
	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	content, err := os.ReadFile(hookPath)
	require.NoError(t, err)

	assert.True(t, containsMarker(string(content)))
	assert.Contains(t, string(content), "verdict scan")
}

func TestRunHookStatus_NoHook(t *testing.T) {
	// Create a temporary directory with .git but no hook
	tmpDir, err := os.MkdirTemp("", "hook-status-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	err = os.Mkdir(gitDir, 0755)
	require.NoError(t, err)

	// Create hooks directory (empty)
	hooksDir := filepath.Join(gitDir, "hooks")
	err = os.Mkdir(hooksDir, 0755)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Save original noColor
	oldNoColor := noColor
	noColor = true
	defer func() { noColor = oldNoColor }()

	// Change to tmp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Run status - should not error, just report no hook
	err = runHookStatus(nil, nil)
	assert.NoError(t, err)
}

func TestRunHookUninstall_NoHook(t *testing.T) {
	// Create a temporary directory with .git but no hook
	tmpDir, err := os.MkdirTemp("", "hook-uninstall-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	err = os.Mkdir(gitDir, 0755)
	require.NoError(t, err)

	// Create hooks directory (empty)
	hooksDir := filepath.Join(gitDir, "hooks")
	err = os.Mkdir(hooksDir, 0755)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Save original noColor
	oldNoColor := noColor
	noColor = true
	defer func() { noColor = oldNoColor }()

	// Change to tmp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Run uninstall - should not error when no hook exists
	err = runHookUninstall(nil, nil)
	assert.NoError(t, err)
}

func TestRunHookUninstall_WithHook(t *testing.T) {
	// Create a temporary directory with .git and hook
	tmpDir, err := os.MkdirTemp("", "hook-uninstall-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create .git/hooks directory
	hooksDir := filepath.Join(tmpDir, ".git", "hooks")
	err = os.MkdirAll(hooksDir, 0755)
	require.NoError(t, err)

	// Create a verdict hook
	hookPath := filepath.Join(hooksDir, "pre-commit")
	hookContent := hookMarker + "\necho test"
	err = os.WriteFile(hookPath, []byte(hookContent), 0755)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Save original noColor
	oldNoColor := noColor
	noColor = true
	defer func() { noColor = oldNoColor }()

	// Change to tmp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Run uninstall
	err = runHookUninstall(nil, nil)
	require.NoError(t, err)

	// Verify hook was removed
	_, err = os.Stat(hookPath)
	assert.True(t, os.IsNotExist(err))
}

func TestRunHookUninstall_NonVerdictHook(t *testing.T) {
	// Create a temporary directory with .git and non-verdict hook
	tmpDir, err := os.MkdirTemp("", "hook-uninstall-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create .git/hooks directory
	hooksDir := filepath.Join(tmpDir, ".git", "hooks")
	err = os.MkdirAll(hooksDir, 0755)
	require.NoError(t, err)

	// Create a non-verdict hook
	hookPath := filepath.Join(hooksDir, "pre-commit")
	err = os.WriteFile(hookPath, []byte("#!/bin/bash\necho other hook"), 0755)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Save original noColor
	oldNoColor := noColor
	noColor = true
	defer func() { noColor = oldNoColor }()

	// Change to tmp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Run uninstall - should error because it's not a verdict hook
	err = runHookUninstall(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a VerdictSec hook")

	// Verify hook was NOT removed
	_, err = os.Stat(hookPath)
	assert.NoError(t, err)
}
