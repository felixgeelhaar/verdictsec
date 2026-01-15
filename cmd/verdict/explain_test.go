package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExplainCmd_Init(t *testing.T) {
	// Verify explain command is properly initialized
	assert.NotNil(t, explainCmd)
	assert.Equal(t, "explain <finding-id>", explainCmd.Use)

	// Check flags exist
	flags := explainCmd.Flags()
	require.NotNil(t, flags)

	providerFlag := flags.Lookup("provider")
	assert.NotNil(t, providerFlag)
}

func TestRunExplain_ConfigError(t *testing.T) {
	// Test with nonexistent config - should return config error
	oldCfgFile := cfgFile
	cfgFile = "/nonexistent/config.yaml"
	defer func() { cfgFile = oldCfgFile }()

	err := runExplain(nil, []string{"finding-123"})
	assert.Error(t, err)
}
