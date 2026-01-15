package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompletionCmd_Init(t *testing.T) {
	// Verify completion command is properly initialized
	assert.NotNil(t, completionCmd)
	assert.Equal(t, "completion [bash|zsh|fish|powershell]", completionCmd.Use)

	// Check valid args
	assert.Contains(t, completionCmd.ValidArgs, "bash")
	assert.Contains(t, completionCmd.ValidArgs, "zsh")
	assert.Contains(t, completionCmd.ValidArgs, "fish")
	assert.Contains(t, completionCmd.ValidArgs, "powershell")
}

func TestCompletionCmd_Bash(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := completionCmd.RunE(completionCmd, []string{"bash"})

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Bash completion should contain certain patterns
	assert.Contains(t, output, "bash completion")
}

func TestCompletionCmd_Zsh(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := completionCmd.RunE(completionCmd, []string{"zsh"})

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Zsh completion should have output
	assert.NotEmpty(t, output)
}

func TestCompletionCmd_Fish(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := completionCmd.RunE(completionCmd, []string{"fish"})

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Fish completion should have output
	assert.NotEmpty(t, output)
}

func TestCompletionCmd_Powershell(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := completionCmd.RunE(completionCmd, []string{"powershell"})

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Powershell completion should have output
	assert.NotEmpty(t, output)
}

func TestCompletionCmd_InvalidShell(t *testing.T) {
	err := completionCmd.RunE(completionCmd, []string{"invalid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported shell")
}
