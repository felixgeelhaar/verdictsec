package gosec

import (
	"context"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func TestNewAdapter(t *testing.T) {
	adapter := NewAdapter()

	assert.NotNil(t, adapter)
	assert.Equal(t, "gosec", adapter.binaryPath)
}

func TestNewAdapterWithPath(t *testing.T) {
	adapter := NewAdapterWithPath("/custom/path/gosec")

	assert.NotNil(t, adapter)
	assert.Equal(t, "/custom/path/gosec", adapter.binaryPath)
}

func TestAdapter_ID(t *testing.T) {
	adapter := NewAdapter()

	assert.Equal(t, ports.EngineGosec, adapter.ID())
}

func TestAdapter_Capabilities(t *testing.T) {
	adapter := NewAdapter()

	caps := adapter.Capabilities()

	assert.Len(t, caps, 1)
	assert.Contains(t, caps, ports.CapabilitySAST)
}

func TestAdapter_IsAvailable(t *testing.T) {
	// Test with default path - may or may not be available
	adapter := NewAdapter()
	// Just verify it returns a boolean without error
	_ = adapter.IsAvailable()

	// Test with invalid path - should not be available
	adapterBadPath := NewAdapterWithPath("/nonexistent/gosec")
	assert.False(t, adapterBadPath.IsAvailable())
}

func TestAdapter_Version_Unknown(t *testing.T) {
	// Test with invalid path - should return "unknown"
	adapter := NewAdapterWithPath("/nonexistent/gosec")

	version := adapter.Version()

	assert.Equal(t, "unknown", version)
}

func TestAdapter_Version_Cached(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/gosec")

	// Call Version twice - should cache the result
	version1 := adapter.Version()
	version2 := adapter.Version()

	assert.Equal(t, version1, version2)
	assert.Equal(t, "unknown", version1)
}

func TestAdapter_Run_BinaryNotFound(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/gosec")
	target := ports.NewTarget("/test/path")
	config := ports.DefaultConfig()

	_, _, err := adapter.Run(context.Background(), target, config.Engines[ports.EngineGosec])

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Gosec not found")
}

func TestAdapter_BuildArgs_Default(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{Enabled: true}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-fmt=json")
	assert.Contains(t, args, "-stdout")
	assert.Contains(t, args, "-quiet")
	assert.Contains(t, args, "./...")
}

func TestAdapter_BuildArgs_WithMinSeverity(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:     true,
		MinSeverity: finding.SeverityHigh,
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-severity=HIGH")
}

func TestAdapter_BuildArgs_WithExclusions(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:    true,
		ExcludeIDs: []string{"G101", "G104"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-exclude=G101")
	assert.Contains(t, args, "-exclude=G104")
}

func TestAdapter_BuildArgs_WithPathExclusions(t *testing.T) {
	adapter := NewAdapter()
	target := ports.Target{
		Path:       "/test/path",
		Exclusions: []string{"vendor", "testdata"},
	}
	config := ports.EngineConfig{Enabled: true}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-exclude-dir=vendor,testdata")
}

func TestSeverityToGosec(t *testing.T) {
	tests := []struct {
		severity finding.Severity
		expected string
	}{
		{finding.SeverityCritical, "HIGH"},
		{finding.SeverityHigh, "HIGH"},
		{finding.SeverityMedium, "MEDIUM"},
		{finding.SeverityLow, "LOW"},
		{finding.SeverityUnknown, "LOW"},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			result := severityToGosec(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAdapter_ImplementsEngineInterface(t *testing.T) {
	var _ ports.Engine = (*Adapter)(nil)

	adapter := NewAdapter()

	// Verify all interface methods are implemented
	_ = adapter.ID()
	_ = adapter.Version()
	_ = adapter.Capabilities()
	_ = adapter.IsAvailable()
}

func TestAdapter_Run_ContextCancellation(t *testing.T) {
	// Skip if gosec is not available
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("gosec not available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	target := ports.NewTarget("/test/path")
	config := ports.DefaultConfig()

	_, _, err := adapter.Run(ctx, target, config.Engines[ports.EngineGosec])

	// Should error due to context cancellation
	assert.Error(t, err)
}

func TestAdapter_Info(t *testing.T) {
	adapter := NewAdapter()

	info := adapter.Info()

	assert.Equal(t, ports.EngineGosec, info.ID)
	assert.Equal(t, "Gosec", info.Name)
	assert.NotEmpty(t, info.Description)
	assert.Contains(t, info.InstallCmd, "github.com/securego/gosec")
	assert.Equal(t, "https://github.com/securego/gosec", info.Homepage)
	assert.Equal(t, ports.CapabilitySAST, info.Capability)
}
