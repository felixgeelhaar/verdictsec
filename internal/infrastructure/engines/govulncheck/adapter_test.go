package govulncheck

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
	assert.Equal(t, "govulncheck", adapter.binaryPath)
}

func TestNewAdapterWithPath(t *testing.T) {
	adapter := NewAdapterWithPath("/custom/path/govulncheck")

	assert.NotNil(t, adapter)
	assert.Equal(t, "/custom/path/govulncheck", adapter.binaryPath)
}

func TestAdapter_ID(t *testing.T) {
	adapter := NewAdapter()

	assert.Equal(t, ports.EngineGovulncheck, adapter.ID())
}

func TestAdapter_Capabilities(t *testing.T) {
	adapter := NewAdapter()

	caps := adapter.Capabilities()

	assert.Len(t, caps, 1)
	assert.Contains(t, caps, ports.CapabilityVuln)
}

func TestAdapter_IsAvailable(t *testing.T) {
	// Test with invalid path - should not be available
	adapter := NewAdapterWithPath("/nonexistent/govulncheck")
	assert.False(t, adapter.IsAvailable())
}

func TestAdapter_Version_Unknown(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/govulncheck")

	version := adapter.Version()

	assert.Equal(t, "unknown", version)
}

func TestAdapter_Run_BinaryNotFound(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/govulncheck")
	target := ports.NewTarget("/test/path")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "govulncheck binary not found")
}

func TestAdapter_BuildArgs_Default(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{Enabled: true, Settings: make(map[string]string)}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-format=json")
	assert.Contains(t, args, "./...")
}

func TestAdapter_BuildArgs_WithMode(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"mode": "binary"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-mode=binary")
}

func TestSeverityFromCVSS(t *testing.T) {
	tests := []struct {
		score    float64
		expected finding.Severity
	}{
		{9.5, finding.SeverityCritical},
		{9.0, finding.SeverityCritical},
		{8.5, finding.SeverityHigh},
		{7.0, finding.SeverityHigh},
		{5.5, finding.SeverityMedium},
		{4.0, finding.SeverityMedium},
		{2.5, finding.SeverityLow},
		{0.1, finding.SeverityLow},
		{0.0, finding.SeverityUnknown},
		{-1.0, finding.SeverityUnknown},
	}

	for _, tt := range tests {
		result := severityFromCVSS(tt.score)
		assert.Equal(t, tt.expected, result, "Score: %f", tt.score)
	}
}

func TestAdapter_ImplementsEngineInterface(t *testing.T) {
	var _ ports.Engine = (*Adapter)(nil)
}

func TestAdapter_Run_InvalidPath(t *testing.T) {
	adapter := NewAdapter()
	// Path with null bytes is invalid
	target := ports.NewTarget("/test/path\x00invalid")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)

	assert.Error(t, err)
}

func TestAdapter_Version_Cached(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/govulncheck")
	adapter.version = "v1.0.0"

	version := adapter.Version()

	assert.Equal(t, "v1.0.0", version)
}

func TestAdapter_BuildArgs_SourceMode(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"mode": "source"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-mode=source")
}

func TestAdapter_BuildArgs_EmptySettings(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: make(map[string]string),
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-format=json")
	assert.Contains(t, args, "./...")
	// Without mode setting, only basic args
	assert.Len(t, args, 2)
}

func TestSeverityFromCVSS_EdgeCases(t *testing.T) {
	// Test edge cases based on actual thresholds
	// >= 9.0: Critical
	// >= 7.0: High
	// >= 4.0: Medium
	// > 0: Low
	// else: Unknown
	assert.Equal(t, finding.SeverityCritical, severityFromCVSS(10.0))
	assert.Equal(t, finding.SeverityHigh, severityFromCVSS(8.9))      // 8.9 < 9.0 -> High
	assert.Equal(t, finding.SeverityMedium, severityFromCVSS(6.9))    // 6.9 < 7.0 -> Medium
	assert.Equal(t, finding.SeverityLow, severityFromCVSS(3.9))       // 3.9 < 4.0 -> Low
	assert.Equal(t, finding.SeverityLow, severityFromCVSS(0.1))       // 0.1 > 0 -> Low
	assert.Equal(t, finding.SeverityUnknown, severityFromCVSS(0.0))   // 0.0 -> Unknown
}
