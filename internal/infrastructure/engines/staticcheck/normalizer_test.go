package staticcheck

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNormalizer(t *testing.T) {
	normalizer := NewNormalizer()
	assert.NotNil(t, normalizer)
	assert.NotNil(t, normalizer.ruleOverrides)
}

func TestNewNormalizerWithOverrides(t *testing.T) {
	overrides := map[string]finding.Severity{
		"U1000": finding.SeverityLow,
	}

	normalizer := NewNormalizerWithOverrides(overrides)

	assert.NotNil(t, normalizer)
	assert.Equal(t, finding.SeverityLow, normalizer.ruleOverrides["U1000"])
}

func TestNormalizer_Normalize(t *testing.T) {
	normalizer := NewNormalizer()

	raw := ports.RawFinding{
		RuleID:      "U1000",
		Message:     "func unused is unused",
		Severity:    "error",
		Confidence:  "HIGH",
		File:        "/path/to/main.go",
		StartLine:   11,
		StartColumn: 6,
		EndLine:     11,
		EndColumn:   20,
		Metadata: map[string]string{
			"check_code": "U1000",
		},
	}

	result := normalizer.Normalize(ports.EngineStaticcheck, raw)

	require.NotNil(t, result)
	assert.Equal(t, finding.FindingTypeSAST, result.Type())
	assert.Equal(t, "staticcheck", result.EngineID())
	assert.Equal(t, "U1000", result.RuleID())
	assert.Equal(t, "func unused is unused", result.Title())
	assert.Equal(t, finding.SeverityInfo, result.NormalizedSeverity())
	assert.Equal(t, finding.ConfidenceHigh, result.Confidence())
}

func TestNormalizer_Normalize_Location(t *testing.T) {
	normalizer := NewNormalizer()

	raw := ports.RawFinding{
		RuleID:      "U1000",
		Message:     "func unused is unused",
		Severity:    "error",
		Confidence:  "HIGH",
		File:        "/path/to/main.go",
		StartLine:   11,
		StartColumn: 6,
		EndLine:     15,
		EndColumn:   20,
	}

	result := normalizer.Normalize(ports.EngineStaticcheck, raw)

	require.NotNil(t, result)
	loc := result.Location()
	assert.Equal(t, "/path/to/main.go", loc.File())
	assert.Equal(t, 11, loc.Line())
	assert.Equal(t, 6, loc.Column())
	assert.Equal(t, 15, loc.EndLine())
	assert.Equal(t, 20, loc.EndColumn())
}

func TestNormalizer_Normalize_WithOverride(t *testing.T) {
	overrides := map[string]finding.Severity{
		"U1000": finding.SeverityMedium,
	}
	normalizer := NewNormalizerWithOverrides(overrides)

	raw := ports.RawFinding{
		RuleID:   "U1000",
		Message:  "func unused is unused",
		Severity: "error",
	}

	result := normalizer.Normalize(ports.EngineStaticcheck, raw)

	require.NotNil(t, result)
	assert.Equal(t, finding.SeverityMedium, result.NormalizedSeverity())
}

func TestNormalizer_Normalize_Metadata(t *testing.T) {
	normalizer := NewNormalizer()

	raw := ports.RawFinding{
		RuleID:   "U1000",
		Message:  "func unused is unused",
		Severity: "error",
		Metadata: map[string]string{
			"check_code": "U1000",
		},
	}

	result := normalizer.Normalize(ports.EngineStaticcheck, raw)

	require.NotNil(t, result)
	// Check that metadata is preserved
	assert.Equal(t, "U1000", result.Metadata()["check_code"])
}

func TestNormalizer_DefaultRuleOverrides(t *testing.T) {
	overrides := defaultRuleOverrides()

	// U1000 should map to Info by default
	assert.Equal(t, finding.SeverityInfo, overrides["U1000"])
}

func TestNormalizer_NormalizeSeverity_WithOverride(t *testing.T) {
	normalizer := NewNormalizer()

	// U1000 has override to Info
	severity := normalizer.normalizeSeverity("U1000")
	assert.Equal(t, finding.SeverityInfo, severity)
}

func TestNormalizer_NormalizeSeverity_UnknownRule(t *testing.T) {
	normalizer := NewNormalizer()

	// Unknown rule should default to Info
	severity := normalizer.normalizeSeverity("UNKNOWN_RULE")
	assert.Equal(t, finding.SeverityInfo, severity)
}

func TestGetRuleDescription(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"U1000", "Unused code (functions, types, constants, variables)"},
		{"UNKNOWN", "Unknown staticcheck rule"},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			desc := GetRuleDescription(tt.ruleID)
			assert.Equal(t, tt.expected, desc)
		})
	}
}

func TestNormalizer_Normalize_FindingType(t *testing.T) {
	normalizer := NewNormalizer()

	raw := ports.RawFinding{
		RuleID:   "U1000",
		Message:  "func unused is unused",
		Severity: "error",
	}

	result := normalizer.Normalize(ports.EngineStaticcheck, raw)

	require.NotNil(t, result)
	// Staticcheck findings should be SAST type
	assert.Equal(t, finding.FindingTypeSAST, result.Type())
}

func TestNormalizer_Normalize_Confidence(t *testing.T) {
	normalizer := NewNormalizer()

	raw := ports.RawFinding{
		RuleID:     "U1000",
		Message:    "func unused is unused",
		Severity:   "error",
		Confidence: "HIGH", // Parser sets this
	}

	result := normalizer.Normalize(ports.EngineStaticcheck, raw)

	require.NotNil(t, result)
	// Staticcheck has high confidence
	assert.Equal(t, finding.ConfidenceHigh, result.Confidence())
}

func TestNormalizer_Normalize_Fingerprint(t *testing.T) {
	normalizer := NewNormalizer()

	raw := ports.RawFinding{
		RuleID:      "U1000",
		Message:     "func unused is unused",
		Severity:    "error",
		File:        "/path/to/main.go",
		StartLine:   11,
		StartColumn: 6,
		EndLine:     11,
		EndColumn:   20,
	}

	result := normalizer.Normalize(ports.EngineStaticcheck, raw)

	require.NotNil(t, result)
	// Fingerprint should be non-empty and consistent
	fp := result.Fingerprint()
	assert.NotEmpty(t, fp.Value())
	assert.Len(t, fp.Value(), 32) // SHA-256 truncated to 128 bits = 32 hex chars
}

func TestNormalizer_Normalize_DifferentFindingsDifferentFingerprints(t *testing.T) {
	normalizer := NewNormalizer()

	raw1 := ports.RawFinding{
		RuleID:    "U1000",
		Message:   "func unused1 is unused",
		File:      "/path/to/main.go",
		StartLine: 11,
	}

	raw2 := ports.RawFinding{
		RuleID:    "U1000",
		Message:   "func unused2 is unused",
		File:      "/path/to/main.go",
		StartLine: 20, // Different line
	}

	result1 := normalizer.Normalize(ports.EngineStaticcheck, raw1)
	result2 := normalizer.Normalize(ports.EngineStaticcheck, raw2)

	require.NotNil(t, result1)
	require.NotNil(t, result2)

	// Different locations should produce different fingerprints
	assert.NotEqual(t, result1.Fingerprint().Value(), result2.Fingerprint().Value())
}
