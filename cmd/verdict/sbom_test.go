package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSBOMDiffCmd_Init(t *testing.T) {
	// Verify sbom command is properly initialized
	assert.NotNil(t, sbomDiffCmd)
	assert.Equal(t, "diff <base> <target>", sbomDiffCmd.Use)

	// Check flags exist
	flags := sbomDiffCmd.Flags()
	require.NotNil(t, flags)

	jsonFlag := flags.Lookup("json")
	assert.NotNil(t, jsonFlag)

	markdownFlag := flags.Lookup("markdown")
	assert.NotNil(t, markdownFlag)
}

func TestRunSBOMDiff_InvalidFiles(t *testing.T) {
	// Test with nonexistent files - should return error
	err := runSBOMDiff(nil, []string{"/nonexistent/old.json", "/nonexistent/new.json"})
	assert.Error(t, err)
}
