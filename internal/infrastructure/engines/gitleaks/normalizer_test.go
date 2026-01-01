package gitleaks

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
	customOverrides := map[string]finding.Severity{
		"custom-rule":       finding.SeverityLow,
		"aws-access-key-id": finding.SeverityMedium, // Override default
	}

	normalizer := NewNormalizerWithOverrides(customOverrides)

	require.NotNil(t, normalizer)

	// Custom rule should be added
	raw := ports.RawFinding{
		RuleID:   "custom-rule",
		Severity: "HIGH",
		File:     "test.go",
	}
	result := normalizer.Normalize(ports.EngineGitleaks, raw)
	assert.Equal(t, finding.SeverityLow, result.NormalizedSeverity())

	// Override should replace default
	rawAws := ports.RawFinding{
		RuleID:   "aws-access-key-id",
		Severity: "CRITICAL",
		File:     "test.go",
	}
	resultAws := normalizer.Normalize(ports.EngineGitleaks, rawAws)
	assert.Equal(t, finding.SeverityMedium, resultAws.NormalizedSeverity())

	// Other defaults should remain
	rawPrivate := ports.RawFinding{
		RuleID:   "private-key",
		Severity: "HIGH",
		File:     "test.go",
	}
	resultPrivate := normalizer.Normalize(ports.EngineGitleaks, rawPrivate)
	assert.Equal(t, finding.SeverityCritical, resultPrivate.NormalizedSeverity())
}

func TestNormalizer_Normalize(t *testing.T) {
	normalizer := NewNormalizer()
	raw := ports.RawFinding{
		RuleID:      "aws-access-key-id",
		Message:     "AWS Access Key ID detected",
		Severity:    "HIGH",
		Confidence:  "HIGH",
		File:        "config.go",
		StartLine:   10,
		StartColumn: 5,
		EndLine:     10,
		EndColumn:   25,
		Snippet:     "[REDACTED]",
		Metadata: map[string]string{
			"commit":              "abc123",
			"gitleaks_fingerprint": "config.go:10:aws-access-key-id",
		},
	}

	result := normalizer.Normalize(ports.EngineGitleaks, raw)

	require.NotNil(t, result)
	assert.Equal(t, finding.FindingTypeSecret, result.Type())
	assert.Equal(t, "gitleaks", result.EngineID())
	assert.Equal(t, "aws-access-key-id", result.RuleID())
	assert.Equal(t, finding.SeverityCritical, result.NormalizedSeverity()) // Has override
	assert.Equal(t, finding.ConfidenceHigh, result.Confidence())
	assert.Equal(t, "798", result.CWEID()) // CWE-798: Hardcoded credentials
}

func TestNormalizer_Normalize_WithRuleOverride(t *testing.T) {
	normalizer := NewNormalizer()

	tests := []struct {
		ruleID           string
		expectedSeverity finding.Severity
	}{
		{"aws-access-key-id", finding.SeverityCritical},
		{"aws-secret-access-key", finding.SeverityCritical},
		{"private-key", finding.SeverityCritical},
		{"github-pat", finding.SeverityCritical},
		{"generic-api-key", finding.SeverityHigh},
		{"unknown-rule", finding.SeverityHigh}, // Defaults to HIGH
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			raw := ports.RawFinding{
				RuleID:   tt.ruleID,
				Severity: "HIGH",
				File:     "test.go",
			}

			result := normalizer.Normalize(ports.EngineGitleaks, raw)

			assert.Equal(t, tt.expectedSeverity, result.NormalizedSeverity())
		})
	}
}

func TestNormalizer_Normalize_LowEntropy(t *testing.T) {
	normalizer := NewNormalizer()
	raw := ports.RawFinding{
		RuleID:     "generic-secret",
		Severity:   "HIGH",
		Confidence: "HIGH",
		File:       "test.go",
		Metadata: map[string]string{
			"entropy": "1.5", // Low entropy
		},
	}

	result := normalizer.Normalize(ports.EngineGitleaks, raw)

	// Low entropy should reduce confidence
	assert.Equal(t, finding.ConfidenceMedium, result.Confidence())
}

func TestNormalizeSeverity(t *testing.T) {
	normalizer := NewNormalizer()

	tests := []struct {
		ruleID      string
		rawSeverity string
		expected    finding.Severity
	}{
		// With override
		{"aws-access-key-id", "MEDIUM", finding.SeverityCritical},

		// Without override - use raw severity
		{"unknown-rule", "HIGH", finding.SeverityHigh},
		{"unknown-rule", "MEDIUM", finding.SeverityMedium},
		{"unknown-rule", "LOW", finding.SeverityLow},
		{"unknown-rule", "CRITICAL", finding.SeverityCritical},
		{"unknown-rule", "", finding.SeverityHigh}, // Default for secrets
	}

	for _, tt := range tests {
		t.Run(tt.ruleID+"_"+tt.rawSeverity, func(t *testing.T) {
			result := normalizer.normalizeSeverity(tt.ruleID, tt.rawSeverity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultRuleOverrides(t *testing.T) {
	overrides := defaultRuleOverrides()

	// Verify critical rules
	assert.Equal(t, finding.SeverityCritical, overrides["aws-access-key-id"])
	assert.Equal(t, finding.SeverityCritical, overrides["private-key"])
	assert.Equal(t, finding.SeverityCritical, overrides["github-pat"])

	// Verify high severity rules
	assert.Equal(t, finding.SeverityHigh, overrides["generic-api-key"])
	assert.Equal(t, finding.SeverityHigh, overrides["slack-webhook"])
}

func TestGetRuleDescription(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"aws-access-key-id", "AWS Access Key ID"},
		{"private-key", "Private Key"},
		{"github-pat", "GitHub Personal Access Token"},
		{"unknown-rule", "Secret detected"},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			result := GetRuleDescription(tt.ruleID)
			assert.Equal(t, tt.expected, result)
		})
	}
}
