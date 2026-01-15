package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTUICmd_Init(t *testing.T) {
	// Verify TUI command is properly initialized
	assert.NotNil(t, tuiCmd)
	assert.Equal(t, "tui [path]", tuiCmd.Use)

	// Check flags exist
	flags := tuiCmd.Flags()
	require.NotNil(t, flags)

	baselineFlag := flags.Lookup("baseline")
	assert.NotNil(t, baselineFlag)

	excludeFlag := flags.Lookup("exclude")
	assert.NotNil(t, excludeFlag)

	includeFlag := flags.Lookup("include")
	assert.NotNil(t, includeFlag)

	noInlineFlag := flags.Lookup("no-inline")
	assert.NotNil(t, noInlineFlag)
}

func TestRunTUI_ConfigError(t *testing.T) {
	// Test with nonexistent config - should return config error
	oldCfgFile := cfgFile
	cfgFile = "/nonexistent/config.yaml"
	defer func() { cfgFile = oldCfgFile }()

	err := runTUI(nil, nil)
	assert.Error(t, err)
}
