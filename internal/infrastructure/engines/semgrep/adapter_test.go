package semgrep

import (
	"context"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAdapter(t *testing.T) {
	adapter := NewAdapter()
	assert.NotNil(t, adapter)
}

func TestAdapter_ID(t *testing.T) {
	adapter := NewAdapter()
	assert.Equal(t, ports.EngineSemgrep, adapter.ID())
}

func TestAdapter_Capabilities(t *testing.T) {
	adapter := NewAdapter()
	caps := adapter.Capabilities()

	assert.Len(t, caps, 1)
	assert.Equal(t, ports.CapabilitySAST, caps[0])
}

func TestAdapter_Info(t *testing.T) {
	adapter := NewAdapter()
	info := adapter.Info()

	assert.Equal(t, ports.EngineSemgrep, info.ID)
	assert.Equal(t, "Semgrep", info.Name)
	assert.Contains(t, info.Description, "static analysis")
	assert.Contains(t, info.InstallCmd, "semgrep")
	assert.Contains(t, info.Homepage, "semgrep")
	assert.Equal(t, ports.CapabilitySAST, info.Capability)
}

func TestAdapter_IsAvailable(t *testing.T) {
	adapter := NewAdapter()
	// This test depends on whether semgrep is installed
	// We just verify the method doesn't panic
	_ = adapter.IsAvailable()
}

func TestAdapter_Version(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("semgrep not available")
	}

	version := adapter.Version()
	assert.NotEmpty(t, version)
}

func TestAdapter_Version_Caching(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("semgrep not available")
	}

	// First call
	version1 := adapter.Version()
	// Second call should return cached value
	version2 := adapter.Version()

	assert.Equal(t, version1, version2)
}

func TestAdapter_BuildArgs(t *testing.T) {
	adapter := NewAdapter()

	target := ports.Target{
		Path:       "/test/path",
		Exclusions: []string{"vendor/", "testdata/"},
	}

	config := ports.EngineConfig{
		Enabled: true,
		Settings: map[string]string{
			"config":   "p/golang",
			"severity": "ERROR",
		},
		ExcludeIDs: []string{"go-jwt-hardcoded-secret"},
	}

	args := adapter.buildArgs(target, config)

	// Should include JSON format
	assert.Contains(t, args, "--json")

	// Should include quiet mode
	assert.Contains(t, args, "--quiet")

	// Should include config
	assert.Contains(t, args, "--config")
	assert.Contains(t, args, "p/golang")

	// Should include severity filter
	assert.Contains(t, args, "--severity")
	assert.Contains(t, args, "ERROR")

	// Should include rule exclusions
	assert.Contains(t, args, "--exclude-rule")
	assert.Contains(t, args, "go-jwt-hardcoded-secret")

	// Should include path exclusions
	assert.Contains(t, args, "--exclude")
	assert.Contains(t, args, "vendor/")

	// Should include target path
	assert.Contains(t, args, "/test/path")
}

func TestAdapter_BuildArgs_DefaultConfig(t *testing.T) {
	adapter := NewAdapter()

	target := ports.Target{
		Path: "/test/path",
	}

	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{},
	}

	args := adapter.buildArgs(target, config)

	// Should include default auto config
	assert.Contains(t, args, "--config")
	assert.Contains(t, args, "auto")
}

func TestAdapter_Run_InvalidPath(t *testing.T) {
	adapter := NewAdapter()

	target := ports.NewTarget("../../../../../../../invalid")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)
	// Should fail - either path validation or semgrep execution
	require.Error(t, err)
}

func TestAdapter_Run_ContextCancellation(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("semgrep not available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	target := ports.NewTarget(".")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(ctx, target, config)
	// Should fail due to cancelled context
	require.Error(t, err)
}

func TestMapSemgrepSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ERROR", "HIGH"},
		{"error", "HIGH"},
		{"WARNING", "MEDIUM"},
		{"warning", "MEDIUM"},
		{"INFO", "LOW"},
		{"info", "LOW"},
		{"unknown", "MEDIUM"},
		{"", "MEDIUM"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mapSemgrepSeverity(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAdapter_ParseOutput(t *testing.T) {
	adapter := NewAdapter()

	jsonOutput := `{
		"results": [
			{
				"check_id": "go-sql-injection",
				"path": "main.go",
				"start": {"line": 10, "col": 5, "offset": 100},
				"end": {"line": 10, "col": 50, "offset": 145},
				"extra": {
					"message": "SQL injection vulnerability",
					"severity": "ERROR",
					"lines": "db.Query(userInput)",
					"metadata": {
						"cwe": ["CWE-89"]
					}
				}
			}
		],
		"errors": []
	}`

	config := ports.DefaultEngineConfig()
	findings, err := adapter.parseOutput([]byte(jsonOutput), config)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "go-sql-injection", f.RuleID)
	assert.Equal(t, "SQL injection vulnerability", f.Message)
	assert.Equal(t, "HIGH", f.Severity)
	assert.Equal(t, "main.go", f.File)
	assert.Equal(t, 10, f.StartLine)
	assert.Equal(t, 5, f.StartColumn)
	assert.Equal(t, "CWE-89", f.Metadata["cwe"])
}

func TestAdapter_ParseOutput_WithExclusions(t *testing.T) {
	adapter := NewAdapter()

	jsonOutput := `{
		"results": [
			{
				"check_id": "go-sql-injection",
				"path": "main.go",
				"start": {"line": 10, "col": 5},
				"end": {"line": 10, "col": 50},
				"extra": {"message": "SQL injection", "severity": "ERROR"}
			},
			{
				"check_id": "excluded-rule",
				"path": "main.go",
				"start": {"line": 20, "col": 5},
				"end": {"line": 20, "col": 50},
				"extra": {"message": "Excluded", "severity": "WARNING"}
			}
		],
		"errors": []
	}`

	config := ports.EngineConfig{
		Enabled:    true,
		ExcludeIDs: []string{"excluded-rule"},
	}

	findings, err := adapter.parseOutput([]byte(jsonOutput), config)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "go-sql-injection", findings[0].RuleID)
}

func TestAdapter_ParseOutput_EmptyResults(t *testing.T) {
	adapter := NewAdapter()

	jsonOutput := `{"results": [], "errors": []}`

	config := ports.DefaultEngineConfig()
	findings, err := adapter.parseOutput([]byte(jsonOutput), config)

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestAdapter_ParseOutput_InvalidJSON(t *testing.T) {
	adapter := NewAdapter()

	config := ports.DefaultEngineConfig()
	_, err := adapter.parseOutput([]byte("invalid json"), config)

	require.Error(t, err)
}

// Verify interface implementation
func TestAdapter_ImplementsEngineInterface(t *testing.T) {
	var _ ports.Engine = (*Adapter)(nil)
}
