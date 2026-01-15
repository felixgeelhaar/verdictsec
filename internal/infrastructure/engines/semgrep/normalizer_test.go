package semgrep

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
		RuleID:      "go-sql-injection",
		Message:     "SQL injection vulnerability detected",
		Severity:    "HIGH",
		Confidence:  "HIGH",
		File:        "main.go",
		StartLine:   10,
		StartColumn: 5,
		EndLine:     10,
		EndColumn:   50,
		Snippet:     "db.Query(userInput)",
		Metadata: map[string]string{
			"cwe": "CWE-89",
			"fix": "Use parameterized queries",
		},
	}

	f := n.Normalize(ports.EngineSemgrep, raw)

	assert.NotNil(t, f)
	assert.Equal(t, finding.FindingTypeSAST, f.Type())
	assert.Equal(t, "semgrep", f.EngineID())
	assert.Equal(t, "go-sql-injection", f.RuleID())
	assert.Contains(t, f.Title(), "SQL injection")
	assert.Equal(t, finding.SeverityHigh, f.NormalizedSeverity())
	assert.Equal(t, finding.ConfidenceHigh, f.Confidence())

	// Check location
	loc := f.Location()
	assert.Equal(t, "main.go", loc.File())
	assert.Equal(t, 10, loc.Line())
	assert.Equal(t, 5, loc.Column())
	assert.Equal(t, 10, loc.EndLine())
	assert.Equal(t, 50, loc.EndColumn())

	// Check metadata
	assert.Equal(t, "db.Query(userInput)", f.Metadata()["snippet"])
	assert.Equal(t, "Use parameterized queries", f.Metadata()["fix"])
	assert.Equal(t, "CWE-89", f.CWEID())
}

func TestNormalizer_Normalize_MinimalFinding(t *testing.T) {
	n := NewNormalizer()

	raw := ports.RawFinding{
		RuleID:    "test-rule",
		Message:   "Test message",
		Severity:  "MEDIUM",
		File:      "test.go",
		StartLine: 1,
		Metadata:  map[string]string{},
	}

	f := n.Normalize(ports.EngineSemgrep, raw)

	assert.NotNil(t, f)
	assert.Equal(t, "test-rule", f.RuleID())
	assert.Equal(t, finding.SeverityMedium, f.NormalizedSeverity())
	assert.Equal(t, finding.ConfidenceMedium, f.Confidence()) // Default
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected finding.Severity
	}{
		{"CRITICAL", finding.SeverityCritical},
		{"critical", finding.SeverityCritical},
		{"HIGH", finding.SeverityHigh},
		{"high", finding.SeverityHigh},
		{"MEDIUM", finding.SeverityMedium},
		{"medium", finding.SeverityMedium},
		{"LOW", finding.SeverityLow},
		{"low", finding.SeverityLow},
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

func TestMapConfidence(t *testing.T) {
	tests := []struct {
		input    string
		expected finding.Confidence
	}{
		{"HIGH", finding.ConfidenceHigh},
		{"high", finding.ConfidenceHigh},
		{"MEDIUM", finding.ConfidenceMedium},
		{"medium", finding.ConfidenceMedium},
		{"LOW", finding.ConfidenceLow},
		{"low", finding.ConfidenceLow},
		{"unknown", finding.ConfidenceMedium},
		{"", finding.ConfidenceMedium},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mapConfidence(tt.input)
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
				File:     "test.go",
				Metadata: map[string]string{},
			}

			f := n.Normalize(ports.EngineSemgrep, raw)
			assert.Equal(t, s.expected, f.NormalizedSeverity())
		})
	}
}
