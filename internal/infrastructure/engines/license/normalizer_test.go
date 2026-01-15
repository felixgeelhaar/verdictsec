package license

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func TestNewNormalizer(t *testing.T) {
	n := NewNormalizer()
	assert.NotNil(t, n)
}

func TestNormalizer_Normalize(t *testing.T) {
	n := NewNormalizer()

	raw := ports.RawFinding{
		RuleID:   "license-agpl-3-0",
		Message:  "Dependency example.com/foo uses AGPL-3.0 license",
		Severity: "CRITICAL",
		File:     "go.mod",
		Metadata: map[string]string{
			"module":      "example.com/foo",
			"license":     "AGPL-3.0",
			"license_url": "https://example.com/LICENSE",
		},
	}

	f := n.Normalize(ports.EngineLicense, raw)

	assert.NotNil(t, f)
	assert.Equal(t, finding.FindingTypeLicense, f.Type())
	assert.Equal(t, "go-licenses", f.EngineID())
	assert.Equal(t, "license-agpl-3-0", f.RuleID())
	assert.Contains(t, f.Title(), "AGPL-3.0")
	assert.Equal(t, finding.SeverityCritical, f.NormalizedSeverity())
	assert.Equal(t, finding.ConfidenceHigh, f.Confidence())

	// Check location
	loc := f.Location()
	assert.Equal(t, "go.mod", loc.File())
	assert.Equal(t, 1, loc.Line())

	// Check metadata
	assert.Equal(t, "example.com/foo", f.Metadata()["module"])
	assert.Equal(t, "AGPL-3.0", f.Metadata()["license"])
	assert.Equal(t, "https://example.com/LICENSE", f.Metadata()["license_url"])
}

func TestNormalizer_MapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected finding.Severity
	}{
		{"CRITICAL", finding.SeverityCritical},
		{"HIGH", finding.SeverityHigh},
		{"MEDIUM", finding.SeverityMedium},
		{"LOW", finding.SeverityLow},
		{"unknown", finding.SeverityUnknown},
		{"", finding.SeverityUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mapSeverity(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizer_AllSeverities(t *testing.T) {
	n := NewNormalizer()

	severities := []struct {
		input    string
		expected finding.Severity
	}{
		{"CRITICAL", finding.SeverityCritical},
		{"HIGH", finding.SeverityHigh},
		{"MEDIUM", finding.SeverityMedium},
		{"LOW", finding.SeverityLow},
	}

	for _, s := range severities {
		t.Run(s.input, func(t *testing.T) {
			raw := ports.RawFinding{
				RuleID:   "test-rule",
				Message:  "Test message",
				Severity: s.input,
				Metadata: map[string]string{
					"module":  "test",
					"license": "test",
				},
			}

			f := n.Normalize(ports.EngineLicense, raw)
			assert.Equal(t, s.expected, f.NormalizedSeverity())
		})
	}
}
