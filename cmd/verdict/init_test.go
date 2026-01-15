package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitCmd_Init(t *testing.T) {
	// Verify init command is properly initialized
	assert.NotNil(t, initCmd)
	assert.Equal(t, "init", initCmd.Use)

	// Check flags exist
	flags := initCmd.Flags()
	require.NotNil(t, flags)

	forceFlag := flags.Lookup("force")
	assert.NotNil(t, forceFlag)
	assert.Equal(t, "f", forceFlag.Shorthand)
}

func TestRunInit_NewProject(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "init-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

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

	// Run init
	err = runInit(nil, nil)
	require.NoError(t, err)

	// Verify .verdict directory was created
	verdictDir := filepath.Join(tmpDir, ".verdict")
	info, err := os.Stat(verdictDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Verify config.yaml was created
	configPath := filepath.Join(verdictDir, "config.yaml")
	_, err = os.Stat(configPath)
	require.NoError(t, err)

	// Verify baseline.json was created
	baselinePath := filepath.Join(verdictDir, "baseline.json")
	content, err := os.ReadFile(baselinePath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "\"version\"")
	assert.Contains(t, string(content), "\"entries\"")
}

func TestRunInit_ExistingConfig_NoForce(t *testing.T) {
	// Create a temporary directory with existing config
	tmpDir, err := os.MkdirTemp("", "init-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create existing .verdict directory and config
	verdictDir := filepath.Join(tmpDir, ".verdict")
	err = os.MkdirAll(verdictDir, 0755)
	require.NoError(t, err)

	configPath := filepath.Join(verdictDir, "config.yaml")
	err = os.WriteFile(configPath, []byte("existing: config"), 0644)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Save original values
	oldNoColor := noColor
	oldInitForce := initForce
	noColor = true
	initForce = false
	defer func() {
		noColor = oldNoColor
		initForce = oldInitForce
	}()

	// Change to tmp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Run init - should fail
	err = runInit(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration already exists")
	assert.Contains(t, err.Error(), "--force")
}

func TestRunInit_ExistingConfig_WithForce(t *testing.T) {
	// Create a temporary directory with existing config
	tmpDir, err := os.MkdirTemp("", "init-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create existing .verdict directory and config
	verdictDir := filepath.Join(tmpDir, ".verdict")
	err = os.MkdirAll(verdictDir, 0755)
	require.NoError(t, err)

	configPath := filepath.Join(verdictDir, "config.yaml")
	err = os.WriteFile(configPath, []byte("existing: config"), 0644)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Save original values
	oldNoColor := noColor
	oldInitForce := initForce
	noColor = true
	initForce = true
	defer func() {
		noColor = oldNoColor
		initForce = oldInitForce
	}()

	// Change to tmp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Run init with force - should succeed
	err = runInit(nil, nil)
	require.NoError(t, err)

	// Verify config was overwritten
	content, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.NotEqual(t, "existing: config", string(content))
}

func TestRunInit_ExistingBaseline(t *testing.T) {
	// Create a temporary directory with existing baseline
	tmpDir, err := os.MkdirTemp("", "init-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create existing .verdict directory and baseline
	verdictDir := filepath.Join(tmpDir, ".verdict")
	err = os.MkdirAll(verdictDir, 0755)
	require.NoError(t, err)

	baselinePath := filepath.Join(verdictDir, "baseline.json")
	existingBaseline := `{"version": "1", "entries": [{"fingerprint": "test"}]}`
	err = os.WriteFile(baselinePath, []byte(existingBaseline), 0644)
	require.NoError(t, err)

	// Save and restore working directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	// Save original values
	oldNoColor := noColor
	oldInitForce := initForce
	noColor = true
	initForce = true // Force to allow overwriting config
	defer func() {
		noColor = oldNoColor
		initForce = oldInitForce
	}()

	// Change to tmp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Run init - should preserve existing baseline
	err = runInit(nil, nil)
	require.NoError(t, err)

	// Verify baseline was NOT overwritten
	content, err := os.ReadFile(baselinePath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "test") // Original fingerprint should still exist
}
