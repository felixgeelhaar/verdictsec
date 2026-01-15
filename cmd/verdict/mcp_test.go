package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPCmd_Init(t *testing.T) {
	// Verify MCP command is properly initialized
	assert.NotNil(t, mcpCmd)
	assert.Equal(t, "mcp", mcpCmd.Use)
}

func TestMCPServeCmd_Init(t *testing.T) {
	assert.NotNil(t, mcpServeCmd)
	assert.Equal(t, "serve", mcpServeCmd.Use)

	// Check flags exist on the serve subcommand
	flags := mcpServeCmd.Flags()
	require.NotNil(t, flags)

	transportFlag := flags.Lookup("transport")
	assert.NotNil(t, transportFlag)
	assert.Equal(t, "t", transportFlag.Shorthand)

	httpAddrFlag := flags.Lookup("http-addr")
	assert.NotNil(t, httpAddrFlag)
}

func TestRunMCPServer_ConfigError(t *testing.T) {
	// Test with nonexistent config - should return config error
	oldCfgFile := cfgFile
	cfgFile = "/nonexistent/config.yaml"
	defer func() { cfgFile = oldCfgFile }()

	err := runMCPServer(nil, nil)
	assert.Error(t, err)
}
