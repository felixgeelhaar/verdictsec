package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixCmd_Init(t *testing.T) {
	// Verify fix command is properly initialized
	assert.NotNil(t, fixCmd)
	assert.Equal(t, "fix [finding-id]", fixCmd.Use)

	// Check flags exist
	flags := fixCmd.Flags()
	require.NotNil(t, flags)

	dryRunFlag := flags.Lookup("dry-run")
	assert.NotNil(t, dryRunFlag)

	noConfirmFlag := flags.Lookup("no-confirm")
	assert.NotNil(t, noConfirmFlag)

	rollbackFlag := flags.Lookup("rollback")
	assert.NotNil(t, rollbackFlag)

	listFlag := flags.Lookup("list")
	assert.NotNil(t, listFlag)
	assert.Equal(t, "l", listFlag.Shorthand)
}

func TestRunFix_ConfigError(t *testing.T) {
	// Test with nonexistent config - should return config error
	oldCfgFile := cfgFile
	cfgFile = "/nonexistent/config.yaml"
	defer func() { cfgFile = oldCfgFile }()

	err := runFix(nil, nil)
	assert.Error(t, err)
}
