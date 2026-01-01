package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCmd(t *testing.T) {
	assert.NotNil(t, rootCmd)
	assert.Equal(t, "verdict-mcp", rootCmd.Use)
	assert.Contains(t, rootCmd.Short, "MCP")
}

func TestRootCmd_Flags(t *testing.T) {
	assert.NotNil(t, rootCmd.Flags().Lookup("transport"))
	assert.NotNil(t, rootCmd.Flags().Lookup("http-addr"))
	assert.NotNil(t, rootCmd.Flags().Lookup("config"))
}

func TestLoadConfig_Default(t *testing.T) {
	// Save and restore global state
	oldConfigPath := configPath
	defer func() {
		configPath = oldConfigPath
	}()

	configPath = ""

	cfg, err := loadConfig()

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "1", cfg.Version)
}

func TestLoadConfig_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: CRITICAL
    warn_on: HIGH
`)
	require.NoError(t, os.WriteFile(cfgPath, content, 0644))

	// Save and restore global state
	oldConfigPath := configPath
	defer func() {
		configPath = oldConfigPath
	}()

	configPath = cfgPath

	cfg, err := loadConfig()

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "CRITICAL", cfg.Policy.Threshold.FailOn)
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	// Save and restore global state
	oldConfigPath := configPath
	defer func() {
		configPath = oldConfigPath
	}()

	configPath = "/nonexistent/path/config.yaml"

	_, err := loadConfig()

	assert.Error(t, err)
}

func TestRunServer_InvalidTransport(t *testing.T) {
	// Save and restore global state
	oldTransport := transport
	oldConfigPath := configPath
	defer func() {
		transport = oldTransport
		configPath = oldConfigPath
	}()

	transport = "invalid-transport"
	configPath = ""

	err := runServer(rootCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported transport")
}

func TestLoadConfig_NonExistentFileReturnsDefault(t *testing.T) {
	// Save and restore global state
	oldConfigPath := configPath
	defer func() {
		configPath = oldConfigPath
	}()

	configPath = ""

	cfg, err := loadConfig()

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	// Should return default config
	assert.Equal(t, "1", cfg.Version)
}

func TestRunServer_ConfigLoadError(t *testing.T) {
	// Save and restore global state
	oldConfigPath := configPath
	defer func() {
		configPath = oldConfigPath
	}()

	configPath = "/nonexistent/path/config.yaml"

	err := runServer(rootCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestRootCmd_LongDescription(t *testing.T) {
	assert.Contains(t, rootCmd.Long, "VerdictSec MCP")
	assert.Contains(t, rootCmd.Long, "verdict_scan")
	assert.Contains(t, rootCmd.Long, "verdict://config")
}

func TestRootCmd_DefaultTransport(t *testing.T) {
	flag := rootCmd.Flags().Lookup("transport")
	require.NotNil(t, flag)
	assert.Equal(t, "stdio", flag.DefValue)
}

func TestRootCmd_DefaultHTTPAddr(t *testing.T) {
	flag := rootCmd.Flags().Lookup("http-addr")
	require.NotNil(t, flag)
	assert.Equal(t, ":8080", flag.DefValue)
}

func TestLoadConfig_WithValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: LOW
  baseline_mode: strict
engines:
  gosec:
    enabled: false
  govulncheck:
    enabled: true
`)
	require.NoError(t, os.WriteFile(cfgPath, content, 0644))

	// Save and restore global state
	oldConfigPath := configPath
	defer func() {
		configPath = oldConfigPath
	}()

	configPath = cfgPath

	cfg, err := loadConfig()

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "HIGH", cfg.Policy.Threshold.FailOn)
	assert.Equal(t, "LOW", cfg.Policy.Threshold.WarnOn)
	assert.Equal(t, "strict", cfg.Policy.BaselineMode)
	assert.False(t, cfg.Engines.Gosec.Enabled)
	assert.True(t, cfg.Engines.Govulncheck.Enabled)
}
