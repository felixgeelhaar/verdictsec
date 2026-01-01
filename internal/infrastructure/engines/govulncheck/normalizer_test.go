package govulncheck

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
}

func TestNormalizer_Normalize(t *testing.T) {
	normalizer := NewNormalizer()
	raw := ports.RawFinding{
		RuleID:      "GO-2023-1234",
		Message:     "SQL injection vulnerability",
		Severity:    "HIGH",
		Confidence:  "HIGH",
		File:        "pkg/db/query.go",
		StartLine:   42,
		StartColumn: 10,
		EndLine:     42,
		EndColumn:   20,
		Metadata: map[string]string{
			"osv_id":              "GO-2023-1234",
			"cve_id":              "CVE-2023-1234",
			"vulnerable_module":   "example.com/sql",
			"vulnerable_version":  "v1.0.0",
			"vulnerable_function": "Query",
			"details":             "Detailed description",
		},
	}

	result := normalizer.Normalize(ports.EngineGovulncheck, raw)

	require.NotNil(t, result)
	assert.Equal(t, finding.FindingTypeVuln, result.Type())
	assert.Equal(t, "govulncheck", result.EngineID())
	assert.Equal(t, "GO-2023-1234", result.RuleID())
	assert.Equal(t, "SQL injection vulnerability", result.Title())
	assert.Equal(t, finding.SeverityHigh, result.NormalizedSeverity())
	assert.Equal(t, finding.ConfidenceHigh, result.Confidence())
	assert.Equal(t, finding.ReachabilityReachable, result.Reachability())
	assert.Equal(t, "CVE-2023-1234", result.CVEID())
}

func TestNormalizer_Normalize_WithoutFunction(t *testing.T) {
	normalizer := NewNormalizer()
	raw := ports.RawFinding{
		RuleID:   "GO-2023-1234",
		Message:  "Test",
		Severity: "HIGH",
		Metadata: map[string]string{
			"osv_id": "GO-2023-1234",
		},
	}

	result := normalizer.Normalize(ports.EngineGovulncheck, raw)

	assert.Equal(t, finding.ReachabilityUnknown, result.Reachability())
}

func TestNormalizeSeverity(t *testing.T) {
	normalizer := NewNormalizer()
	tests := []struct {
		input    string
		expected finding.Severity
	}{
		{"CRITICAL", finding.SeverityCritical},
		{"HIGH", finding.SeverityHigh},
		{"MEDIUM", finding.SeverityMedium},
		{"LOW", finding.SeverityLow},
		{"high", finding.SeverityHigh},
		{"UNKNOWN", finding.SeverityHigh}, // Defaults to HIGH for vulns
		{"", finding.SeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizer.normalizeSeverity("", tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSeverity_WithOverrides(t *testing.T) {
	overrides := map[string]finding.Severity{
		"GO-2023-1234": finding.SeverityCritical,
	}
	normalizer := NewNormalizerWithOverrides(overrides)

	// Override should take precedence
	result := normalizer.normalizeSeverity("GO-2023-1234", "LOW")
	assert.Equal(t, finding.SeverityCritical, result)

	// Non-overridden rule should use default mapping
	result2 := normalizer.normalizeSeverity("GO-2023-9999", "LOW")
	assert.Equal(t, finding.SeverityLow, result2)
}

func TestNormalizeConfidence(t *testing.T) {
	tests := []struct {
		input    string
		expected finding.Confidence
	}{
		{"HIGH", finding.ConfidenceHigh},
		{"MEDIUM", finding.ConfidenceMedium},
		{"LOW", finding.ConfidenceLow},
		{"high", finding.ConfidenceHigh},
		{"UNKNOWN", finding.ConfidenceHigh}, // Defaults to HIGH for govulncheck
		{"", finding.ConfidenceHigh},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeConfidence(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
