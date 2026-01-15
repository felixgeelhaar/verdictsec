package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchCmd_Init(t *testing.T) {
	// Verify watch command is properly initialized
	assert.NotNil(t, watchCmd)
	assert.Equal(t, "watch [path]", watchCmd.Use)

	// Check flags exist
	flags := watchCmd.Flags()
	require.NotNil(t, flags)

	debounceFlag := flags.Lookup("debounce")
	assert.NotNil(t, debounceFlag)

	enginesFlag := flags.Lookup("engines")
	assert.NotNil(t, enginesFlag)
}

func TestRunWatchCmd_ConfigError(t *testing.T) {
	// Test with nonexistent config - should return config error
	oldCfgFile := cfgFile
	cfgFile = "/nonexistent/config.yaml"
	defer func() { cfgFile = oldCfgFile }()

	err := runWatchCmd(nil, nil)
	assert.Error(t, err)
}
