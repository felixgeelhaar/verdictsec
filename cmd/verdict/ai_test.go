package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAICmd_Init(t *testing.T) {
	// Verify AI command is properly initialized
	assert.NotNil(t, aiCmd)
	assert.Equal(t, "ai", aiCmd.Use)
}

func TestAISummarizeCmd_Init(t *testing.T) {
	assert.NotNil(t, aiSummarizeCmd)
	assert.Equal(t, "summarize [path]", aiSummarizeCmd.Use)

	// Check flags exist
	flags := aiSummarizeCmd.Flags()
	require.NotNil(t, flags)

	providerFlag := flags.Lookup("provider")
	assert.NotNil(t, providerFlag)

	scanFlag := flags.Lookup("scan")
	assert.NotNil(t, scanFlag)
}

func TestAIStatusCmd_Init(t *testing.T) {
	assert.NotNil(t, aiStatusCmd)
	assert.Equal(t, "status", aiStatusCmd.Use)
}

func TestRunAISummarize_ConfigError(t *testing.T) {
	// Test with nonexistent config - should return config error
	// Save original config path if any
	oldCfgFile := cfgFile
	cfgFile = "/nonexistent/config.yaml"
	defer func() { cfgFile = oldCfgFile }()

	err := runAISummarize(nil, nil)
	// Error from config loading - this covers the config error path
	assert.Error(t, err)
}

func TestRunAIStatus_ConfigError(t *testing.T) {
	// Test with nonexistent config - should return config error
	oldCfgFile := cfgFile
	cfgFile = "/nonexistent/config.yaml"
	defer func() { cfgFile = oldCfgFile }()

	err := runAIStatus(nil, nil)
	assert.Error(t, err)
}
