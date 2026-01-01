package engines

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCompositeNormalizer(t *testing.T) {
	n := NewCompositeNormalizer()

	require.NotNil(t, n)
	assert.NotNil(t, n.gosecNorm)
	assert.NotNil(t, n.govulncheckNorm)
	assert.NotNil(t, n.gitleaksNorm)
}

func TestCompositeNormalizer_Normalize_Gosec(t *testing.T) {
	n := NewCompositeNormalizer()

	raw := ports.RawFinding{
		RuleID:      "G101",
		Message:     "Potential hardcoded credentials",
		File:        "main.go",
		StartLine:   10,
		StartColumn: 1,
		EndLine:     10,
		EndColumn:   50,
		Severity:    "HIGH",
		Confidence:  "HIGH",
	}

	result := n.Normalize(ports.EngineGosec, raw)

	require.NotNil(t, result)
	assert.Equal(t, "G101", result.RuleID())
	assert.Equal(t, finding.FindingTypeSAST, result.Type())
}

func TestCompositeNormalizer_Normalize_Govulncheck(t *testing.T) {
	n := NewCompositeNormalizer()

	raw := ports.RawFinding{
		RuleID:    "GO-2024-1234",
		Message:   "Vulnerability in package",
		File:      "go.mod",
		StartLine: 5,
		Severity:  "HIGH",
	}

	result := n.Normalize(ports.EngineGovulncheck, raw)

	require.NotNil(t, result)
	assert.Equal(t, "GO-2024-1234", result.RuleID())
	assert.Equal(t, finding.FindingTypeVuln, result.Type())
}

func TestCompositeNormalizer_Normalize_Gitleaks(t *testing.T) {
	n := NewCompositeNormalizer()

	raw := ports.RawFinding{
		RuleID:    "aws-access-key",
		Message:   "AWS access key detected",
		File:      "config.yaml",
		StartLine: 15,
		Severity:  "CRITICAL",
	}

	result := n.Normalize(ports.EngineGitleaks, raw)

	require.NotNil(t, result)
	assert.Equal(t, "aws-access-key", result.RuleID())
	assert.Equal(t, finding.FindingTypeSecret, result.Type())
}

func TestCompositeNormalizer_Normalize_CycloneDX_ReturnsNil(t *testing.T) {
	n := NewCompositeNormalizer()

	raw := ports.RawFinding{
		RuleID:  "sbom-component",
		Message: "SBOM component",
	}

	result := n.Normalize(ports.EngineCycloneDX, raw)

	assert.Nil(t, result)
}

func TestCompositeNormalizer_Normalize_UnknownEngine(t *testing.T) {
	n := NewCompositeNormalizer()

	raw := ports.RawFinding{
		RuleID:      "UNKNOWN-001",
		Message:     "Unknown finding",
		File:        "unknown.go",
		StartLine:   1,
		StartColumn: 1,
		EndLine:     1,
		EndColumn:   10,
	}

	result := n.Normalize(ports.EngineID("unknown-engine"), raw)

	require.NotNil(t, result)
	assert.Equal(t, "UNKNOWN-001", result.RuleID())
	assert.Equal(t, finding.FindingTypeSAST, result.Type())
	assert.Equal(t, finding.SeverityUnknown, result.NormalizedSeverity())
}

func TestCompositeNormalizer_createBasicFinding(t *testing.T) {
	n := NewCompositeNormalizer()

	raw := ports.RawFinding{
		RuleID:      "BASIC-001",
		Message:     "Basic finding message",
		File:        "basic.go",
		StartLine:   5,
		StartColumn: 2,
		EndLine:     5,
		EndColumn:   20,
	}

	result := n.createBasicFinding("test-engine", raw)

	require.NotNil(t, result)
	assert.Equal(t, "BASIC-001", result.RuleID())
	assert.Equal(t, "Basic finding message", result.Title())
	assert.Equal(t, "test-engine", result.EngineID())
	assert.Equal(t, finding.SeverityUnknown, result.NormalizedSeverity())
	assert.Equal(t, "basic.go", result.Location().File())
	assert.Equal(t, 5, result.Location().Line())
}

func TestNewCompositeNormalizerWithConfig(t *testing.T) {
	cfg := NormalizerConfig{
		GosecMappings: map[string]finding.Severity{
			"G101": finding.SeverityCritical,
		},
		GovulncheckMappings: map[string]finding.Severity{
			"GO-2024-1234": finding.SeverityHigh,
		},
		GitleaksMappings: map[string]finding.Severity{
			"aws-access-key": finding.SeverityCritical,
		},
	}

	n := NewCompositeNormalizerWithConfig(cfg)

	require.NotNil(t, n)
	assert.NotNil(t, n.gosecNorm)
	assert.NotNil(t, n.govulncheckNorm)
	assert.NotNil(t, n.gitleaksNorm)
}

func TestNewCompositeNormalizerWithConfig_UsesCustomMappings(t *testing.T) {
	cfg := NormalizerConfig{
		GosecMappings: map[string]finding.Severity{
			"G101": finding.SeverityLow, // Override default (usually CRITICAL)
		},
	}

	n := NewCompositeNormalizerWithConfig(cfg)

	raw := ports.RawFinding{
		RuleID:    "G101",
		Message:   "Potential hardcoded credentials",
		File:      "main.go",
		StartLine: 10,
		Severity:  "HIGH",
	}

	result := n.Normalize(ports.EngineGosec, raw)

	require.NotNil(t, result)
	// Should use the custom mapping (LOW) not the default
	assert.Equal(t, finding.SeverityLow, result.NormalizedSeverity())
}

func TestNewCompositeNormalizerFromPortsConfig(t *testing.T) {
	cfg := ports.Config{
		Engines: map[ports.EngineID]ports.EngineConfig{
			ports.EngineGosec: {
				Enabled: true,
				SeverityMapping: map[string]finding.Severity{
					"G401": finding.SeverityLow,
				},
			},
			ports.EngineGovulncheck: {
				Enabled: true,
				SeverityMapping: map[string]finding.Severity{
					"GO-2024-9999": finding.SeverityMedium,
				},
			},
			ports.EngineGitleaks: {
				Enabled: true,
				SeverityMapping: map[string]finding.Severity{
					"generic-api-key": finding.SeverityHigh,
				},
			},
		},
	}

	n := NewCompositeNormalizerFromPortsConfig(cfg)

	require.NotNil(t, n)
	assert.NotNil(t, n.gosecNorm)
	assert.NotNil(t, n.govulncheckNorm)
	assert.NotNil(t, n.gitleaksNorm)
}

func TestNewCompositeNormalizerFromPortsConfig_UsesCustomMappings(t *testing.T) {
	cfg := ports.Config{
		Engines: map[ports.EngineID]ports.EngineConfig{
			ports.EngineGosec: {
				Enabled: true,
				SeverityMapping: map[string]finding.Severity{
					"G101": finding.SeverityMedium, // Override
				},
			},
		},
	}

	n := NewCompositeNormalizerFromPortsConfig(cfg)

	raw := ports.RawFinding{
		RuleID:    "G101",
		Message:   "Hardcoded credentials",
		File:      "main.go",
		StartLine: 10,
		Severity:  "HIGH",
	}

	result := n.Normalize(ports.EngineGosec, raw)

	require.NotNil(t, result)
	assert.Equal(t, finding.SeverityMedium, result.NormalizedSeverity())
}

func TestNewCompositeNormalizerFromPortsConfig_EmptyConfig(t *testing.T) {
	cfg := ports.Config{
		Engines: map[ports.EngineID]ports.EngineConfig{},
	}

	n := NewCompositeNormalizerFromPortsConfig(cfg)

	require.NotNil(t, n)
	// Should still work with default normalizers
	assert.NotNil(t, n.gosecNorm)
	assert.NotNil(t, n.govulncheckNorm)
	assert.NotNil(t, n.gitleaksNorm)
}

func TestNewCompositeNormalizerFromPortsConfig_NilSeverityMapping(t *testing.T) {
	cfg := ports.Config{
		Engines: map[ports.EngineID]ports.EngineConfig{
			ports.EngineGosec: {
				Enabled:         true,
				SeverityMapping: nil, // Explicitly nil
			},
		},
	}

	n := NewCompositeNormalizerFromPortsConfig(cfg)

	require.NotNil(t, n)
	// Should still create normalizers with defaults
	assert.NotNil(t, n.gosecNorm)
}
