package gosec

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
		"G999": finding.SeverityCritical,
		"G401": finding.SeverityLow, // Override default
	}

	normalizer := NewNormalizerWithOverrides(overrides)

	assert.NotNil(t, normalizer)
	// Check that custom override is present
	assert.Equal(t, finding.SeverityCritical, normalizer.ruleOverrides["G999"])
	// Check that overridden default is updated
	assert.Equal(t, finding.SeverityLow, normalizer.ruleOverrides["G401"])
	// Check that other defaults are preserved
	assert.Equal(t, finding.SeverityCritical, normalizer.ruleOverrides["G101"])
}

func TestNormalizer_Normalize(t *testing.T) {
	normalizer := NewNormalizer()
	raw := ports.RawFinding{
		RuleID:      "G401",
		Message:     "Use of weak cryptographic primitive",
		Severity:    "HIGH",
		Confidence:  "HIGH",
		File:        "/path/to/crypto.go",
		StartLine:   42,
		StartColumn: 10,
		EndLine:     42,
		EndColumn:   30,
		Snippet:     "md5.Sum(data)",
		Metadata: map[string]string{
			"cwe_id": "327",
		},
	}

	result := normalizer.Normalize(ports.EngineGosec, raw)

	require.NotNil(t, result)
	assert.Equal(t, finding.FindingTypeSAST, result.Type())
	assert.Equal(t, "gosec", result.EngineID())
	assert.Equal(t, "G401", result.RuleID())
	assert.Equal(t, "Use of weak cryptographic primitive", result.Title())
	assert.Equal(t, finding.SeverityHigh, result.NormalizedSeverity()) // G401 has override to HIGH
	assert.Equal(t, finding.ConfidenceHigh, result.Confidence())

	loc := result.Location()
	assert.Equal(t, "/path/to/crypto.go", loc.File())
	assert.Equal(t, 42, loc.Line())
	assert.Equal(t, 10, loc.Column())
	assert.Equal(t, 42, loc.EndLine())
	assert.Equal(t, 30, loc.EndColumn())

	assert.Equal(t, "327", result.CWEID())
	assert.Equal(t, "md5.Sum(data)", result.Metadata()["snippet"])
}

func TestNormalizer_Normalize_WithRuleOverride(t *testing.T) {
	normalizer := NewNormalizer()

	tests := []struct {
		ruleID           string
		rawSeverity      string
		expectedSeverity finding.Severity
	}{
		// Rules with overrides - should use override regardless of raw severity
		{"G101", "LOW", finding.SeverityCritical},   // Hardcoded credentials
		{"G201", "MEDIUM", finding.SeverityCritical}, // SQL injection
		{"G204", "HIGH", finding.SeverityCritical},   // Command injection
		{"G304", "MEDIUM", finding.SeverityHigh},     // Path traversal
		{"G104", "HIGH", finding.SeverityLow},        // Errors not checked

		// Rules without overrides - should use raw severity
		{"G999", "HIGH", finding.SeverityHigh},
		{"G999", "MEDIUM", finding.SeverityMedium},
		{"G999", "LOW", finding.SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID+"_"+tt.rawSeverity, func(t *testing.T) {
			raw := ports.RawFinding{
				RuleID:   tt.ruleID,
				Severity: tt.rawSeverity,
				File:     "test.go",
			}

			result := normalizer.Normalize(ports.EngineGosec, raw)

			assert.Equal(t, tt.expectedSeverity, result.NormalizedSeverity())
		})
	}
}

func TestNormalizer_Normalize_Confidence(t *testing.T) {
	normalizer := NewNormalizer()

	tests := []struct {
		rawConfidence      string
		expectedConfidence finding.Confidence
	}{
		{"HIGH", finding.ConfidenceHigh},
		{"MEDIUM", finding.ConfidenceMedium},
		{"LOW", finding.ConfidenceLow},
		{"high", finding.ConfidenceHigh},   // Case insensitive
		{"medium", finding.ConfidenceMedium},
		{"low", finding.ConfidenceLow},
		{"UNKNOWN", finding.ConfidenceUnknown},
		{"", finding.ConfidenceUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.rawConfidence, func(t *testing.T) {
			raw := ports.RawFinding{
				RuleID:     "G999",
				Confidence: tt.rawConfidence,
				File:       "test.go",
			}

			result := normalizer.Normalize(ports.EngineGosec, raw)

			assert.Equal(t, tt.expectedConfidence, result.Confidence())
		})
	}
}

func TestNormalizer_Normalize_NoCWE(t *testing.T) {
	normalizer := NewNormalizer()
	raw := ports.RawFinding{
		RuleID:   "G999",
		Severity: "HIGH",
		File:     "test.go",
		Metadata: map[string]string{},
	}

	result := normalizer.Normalize(ports.EngineGosec, raw)

	assert.Empty(t, result.CWEID())
}

func TestNormalizer_Normalize_NoSnippet(t *testing.T) {
	normalizer := NewNormalizer()
	raw := ports.RawFinding{
		RuleID:   "G999",
		Severity: "HIGH",
		File:     "test.go",
		Snippet:  "",
	}

	result := normalizer.Normalize(ports.EngineGosec, raw)

	_, hasSnippet := result.Metadata()["snippet"]
	assert.False(t, hasSnippet)
}

func TestNormalizeSeverity(t *testing.T) {
	normalizer := NewNormalizer()

	tests := []struct {
		ruleID      string
		rawSeverity string
		expected    finding.Severity
	}{
		// With override
		{"G401", "LOW", finding.SeverityHigh},

		// Without override - use raw severity
		{"G999", "HIGH", finding.SeverityHigh},
		{"G999", "MEDIUM", finding.SeverityMedium},
		{"G999", "LOW", finding.SeverityLow},
		{"G999", "high", finding.SeverityHigh},
		{"G999", "UNKNOWN", finding.SeverityUnknown},
		{"G999", "", finding.SeverityUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID+"_"+tt.rawSeverity, func(t *testing.T) {
			result := normalizer.normalizeSeverity(tt.ruleID, tt.rawSeverity)
			assert.Equal(t, tt.expected, result)
		})
	}
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
		{"Medium", finding.ConfidenceMedium},
		{"low", finding.ConfidenceLow},
		{"INVALID", finding.ConfidenceUnknown},
		{"", finding.ConfidenceUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeConfidence(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultRuleOverrides(t *testing.T) {
	overrides := defaultRuleOverrides()

	// Verify critical rules
	assert.Equal(t, finding.SeverityCritical, overrides["G101"]) // Hardcoded credentials
	assert.Equal(t, finding.SeverityCritical, overrides["G201"]) // SQL injection
	assert.Equal(t, finding.SeverityCritical, overrides["G202"]) // SQL injection
	assert.Equal(t, finding.SeverityCritical, overrides["G204"]) // Command injection

	// Verify high severity rules
	assert.Equal(t, finding.SeverityHigh, overrides["G401"]) // Weak crypto
	assert.Equal(t, finding.SeverityHigh, overrides["G402"]) // TLS InsecureSkipVerify
	assert.Equal(t, finding.SeverityHigh, overrides["G304"]) // Path traversal

	// Verify low severity rules
	assert.Equal(t, finding.SeverityLow, overrides["G104"]) // Errors not checked
	assert.Equal(t, finding.SeverityLow, overrides["G307"]) // Defer in loop
}

func TestGetRuleDescription(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"G101", "Hardcoded credentials"},
		{"G201", "SQL query construction using format string"},
		{"G204", "Subprocess launched with variable"},
		{"G401", "Use of weak cryptographic primitive"},
		{"G402", "TLS InsecureSkipVerify"},
		{"G304", "File path provided as taint input"},
		{"G999", "Unknown gosec rule"},
		{"", "Unknown gosec rule"},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			result := GetRuleDescription(tt.ruleID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizer_ImplementsInterface(t *testing.T) {
	normalizer := NewNormalizer()

	// Test that Normalizer can be used as a FindingNormalizer
	raw := ports.RawFinding{
		RuleID:   "G401",
		Severity: "HIGH",
		File:     "test.go",
	}

	result := normalizer.Normalize(ports.EngineGosec, raw)
	assert.NotNil(t, result)
	assert.Equal(t, finding.FindingTypeSAST, result.Type())
}
