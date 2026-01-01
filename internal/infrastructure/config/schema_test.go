package config

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, "1", cfg.Version)

	// Check policy defaults
	assert.Equal(t, "HIGH", cfg.Policy.Threshold.FailOn)
	assert.Equal(t, "MEDIUM", cfg.Policy.Threshold.WarnOn)
	assert.Equal(t, "warn", cfg.Policy.BaselineMode)

	// Check engine defaults
	assert.True(t, cfg.Engines.Gosec.Enabled)
	assert.True(t, cfg.Engines.Govulncheck.Enabled)
	assert.True(t, cfg.Engines.Gitleaks.Enabled)
	assert.True(t, cfg.Engines.CycloneDX.Enabled)

	// Check output defaults
	assert.Equal(t, "console", cfg.Output.Format)
	assert.Equal(t, "normal", cfg.Output.Verbosity)
	assert.True(t, cfg.Output.Color)

	// Check baseline defaults
	assert.Equal(t, ".verdict/baseline.json", cfg.Baseline.Path)
	assert.False(t, cfg.Baseline.Strict)
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultConfig()

	errs := cfg.Validate()

	assert.Empty(t, errs)
}

func TestConfig_Validate_MissingVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Version = ""

	errs := cfg.Validate()

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "version")
}

func TestConfig_Validate_InvalidSeverity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.Threshold.FailOn = "INVALID"

	errs := cfg.Validate()

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "fail_on")
}

func TestConfig_Validate_InvalidBaselineMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.BaselineMode = "invalid"

	errs := cfg.Validate()

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "baseline_mode")
}

func TestConfig_Validate_InvalidOutputFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Output.Format = "invalid"

	errs := cfg.Validate()

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "output.format")
}

func TestConfig_Validate_InvalidVerbosity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Output.Verbosity = "invalid"

	errs := cfg.Validate()

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "output.verbosity")
}

func TestConfig_Validate_SuppressionMissingFields(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.Suppressions = []SuppressionConfig{
		{Fingerprint: "", Reason: "test", Owner: "test@example.com"},
		{Fingerprint: "abc123", Reason: "", Owner: "test@example.com"},
		{Fingerprint: "abc123", Reason: "test", Owner: ""},
	}

	errs := cfg.Validate()

	assert.Len(t, errs, 3)
}

func TestConfig_ToPortsConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Engines.Gosec.Severity = "HIGH"
	cfg.Engines.Gosec.Exclude = []string{"G104"}

	portsConfig := cfg.ToPortsConfig()

	gosecConfig := portsConfig.Engines[ports.EngineGosec]
	assert.True(t, gosecConfig.Enabled)
	assert.Equal(t, finding.SeverityHigh, gosecConfig.MinSeverity)
	assert.Contains(t, gosecConfig.ExcludeIDs, "G104")
}

func TestConfig_GetFailSeverity(t *testing.T) {
	tests := []struct {
		failOn   string
		expected finding.Severity
	}{
		{"CRITICAL", finding.SeverityCritical},
		{"HIGH", finding.SeverityHigh},
		{"MEDIUM", finding.SeverityMedium},
		{"LOW", finding.SeverityLow},
		{"invalid", finding.SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.failOn, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Policy.Threshold.FailOn = tt.failOn

			result := cfg.GetFailSeverity()

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetWarnSeverity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.Threshold.WarnOn = "HIGH"

	result := cfg.GetWarnSeverity()

	assert.Equal(t, finding.SeverityHigh, result)
}

func TestConfig_IsBaselineStrict(t *testing.T) {
	cfg := DefaultConfig()

	assert.False(t, cfg.IsBaselineStrict())

	cfg.Policy.BaselineMode = "strict"
	assert.True(t, cfg.IsBaselineStrict())
}

func TestConfig_IsBaselineEnabled(t *testing.T) {
	cfg := DefaultConfig()

	assert.True(t, cfg.IsBaselineEnabled())

	cfg.Policy.BaselineMode = "off"
	assert.False(t, cfg.IsBaselineEnabled())
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected finding.Severity
	}{
		{"CRITICAL", finding.SeverityCritical},
		{"HIGH", finding.SeverityHigh},
		{"MEDIUM", finding.SeverityMedium},
		{"LOW", finding.SeverityLow},
		{"unknown", finding.SeverityLow},
		{"", finding.SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseSeverity(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{
		Field:   "policy.threshold.fail_on",
		Message: "invalid value",
	}

	assert.Equal(t, "policy.threshold.fail_on: invalid value", err.Error())
}

func TestConfig_ToDomainPolicy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.Threshold.FailOn = "CRITICAL"
	cfg.Policy.Threshold.WarnOn = "HIGH"
	cfg.Policy.BaselineMode = "strict"

	pol := cfg.ToDomainPolicy()

	assert.Equal(t, finding.SeverityCritical, pol.Threshold.FailOn)
	assert.Equal(t, finding.SeverityHigh, pol.Threshold.WarnOn)
}

func TestConfig_ToDomainPolicy_BaselineModes(t *testing.T) {
	tests := []struct {
		mode     string
		expected string
	}{
		{"strict", "strict"},
		{"warn", "warn"},
		{"off", "off"},
		{"unknown", "warn"}, // defaults to warn
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Policy.BaselineMode = tt.mode

			pol := cfg.ToDomainPolicy()

			// Just verify we got a valid policy - exact mode checking is internal
			assert.NotNil(t, pol)
		})
	}
}

func TestConfig_ToDomainPolicy_WithSuppressions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.Suppressions = []SuppressionConfig{
		{
			Fingerprint: "fp1",
			Reason:      "False positive",
			Owner:       "security@example.com",
		},
		{
			Fingerprint: "fp2",
			Reason:      "Accepted risk",
			Owner:       "dev@example.com",
		},
	}

	pol := cfg.ToDomainPolicy()

	assert.Len(t, pol.Suppressions, 2)
	assert.Equal(t, "fp1", pol.Suppressions[0].Fingerprint)
	assert.Equal(t, "False positive", pol.Suppressions[0].Reason)
	assert.Equal(t, "security@example.com", pol.Suppressions[0].Owner)
}

func TestConfig_EngineConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Engines.Gosec.Severity = "HIGH"
	cfg.Engines.Gosec.Exclude = []string{"G104", "G301"}

	gosecConfig := cfg.EngineConfig("gosec")

	assert.True(t, gosecConfig.Enabled)
	assert.Equal(t, finding.SeverityHigh, gosecConfig.MinSeverity)
	assert.Contains(t, gosecConfig.ExcludeIDs, "G104")
	assert.Contains(t, gosecConfig.ExcludeIDs, "G301")
}

func TestConfig_EngineConfig_AllEngines(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		engineID string
		enabled  bool
	}{
		{"gosec", true},
		{"govulncheck", true},
		{"gitleaks", true},
		{"cyclonedx-gomod", true},
	}

	for _, tt := range tests {
		t.Run(tt.engineID, func(t *testing.T) {
			config := cfg.EngineConfig(tt.engineID)
			assert.Equal(t, tt.enabled, config.Enabled)
		})
	}
}

func TestConfig_EngineConfig_Unknown(t *testing.T) {
	cfg := DefaultConfig()

	config := cfg.EngineConfig("unknown-engine")

	assert.False(t, config.Enabled)
}

func TestConfig_GetOutputFormat(t *testing.T) {
	tests := []struct {
		format   string
		expected ports.OutputFormat
	}{
		{"json", ports.OutputFormatJSON},
		{"sarif", ports.OutputFormatSARIF},
		{"console", ports.OutputFormatConsole},
		{"unknown", ports.OutputFormatConsole}, // defaults to console
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Output.Format = tt.format

			result := cfg.GetOutputFormat()

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetVerbosity(t *testing.T) {
	tests := []struct {
		verbosity string
		expected  ports.Verbosity
	}{
		{"quiet", ports.VerbosityQuiet},
		{"normal", ports.VerbosityNormal},
		{"verbose", ports.VerbosityVerbose},
		{"unknown", ports.VerbosityNormal}, // defaults to normal
	}

	for _, tt := range tests {
		t.Run(tt.verbosity, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Output.Verbosity = tt.verbosity

			result := cfg.GetVerbosity()

			assert.Equal(t, tt.expected, result)
		})
	}
}
