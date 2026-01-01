package writers

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConsoleWriter(t *testing.T) {
	w := NewConsoleWriter()

	assert.NotNil(t, w)
	assert.NotNil(t, w.out)
	assert.NotNil(t, w.err)
	assert.True(t, w.color)
	assert.Equal(t, ports.VerbosityNormal, w.verbosity)
}

func TestNewConsoleWriter_WithOptions(t *testing.T) {
	var buf bytes.Buffer
	var errBuf bytes.Buffer

	w := NewConsoleWriter(
		WithOutput(&buf),
		WithErrorOutput(&errBuf),
		WithColor(false),
		WithVerbosity(ports.VerbosityVerbose),
	)

	assert.Equal(t, &buf, w.out)
	assert.Equal(t, &errBuf, w.err)
	assert.False(t, w.color)
	assert.Equal(t, ports.VerbosityVerbose, w.verbosity)
}

func TestConsoleWriter_SetColor(t *testing.T) {
	w := NewConsoleWriter()

	w.SetColor(false)
	assert.False(t, w.color)

	w.SetColor(true)
	assert.True(t, w.color)
}

func TestConsoleWriter_SetVerbosity(t *testing.T) {
	w := NewConsoleWriter()

	w.SetVerbosity(ports.VerbosityDebug)
	assert.Equal(t, ports.VerbosityDebug, w.verbosity)
}

func TestConsoleWriter_WriteProgress(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(WithOutput(&buf), WithColor(false))

	err := w.WriteProgress("Scanning files...")
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, ">>>")
	assert.Contains(t, output, "Scanning files...")
}

func TestConsoleWriter_WriteProgress_Quiet(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(
		WithOutput(&buf),
		WithVerbosity(ports.VerbosityQuiet),
	)

	err := w.WriteProgress("Should not appear")
	require.NoError(t, err)

	assert.Empty(t, buf.String())
}

func TestConsoleWriter_WriteError(t *testing.T) {
	var errBuf bytes.Buffer
	w := NewConsoleWriter(
		WithErrorOutput(&errBuf),
		WithColor(false),
	)

	testErr := errors.New("something went wrong")
	err := w.WriteError(testErr)
	require.NoError(t, err)

	output := errBuf.String()
	assert.Contains(t, output, "ERROR:")
	assert.Contains(t, output, "something went wrong")
}

func TestConsoleWriter_Flush(t *testing.T) {
	w := NewConsoleWriter()

	err := w.Flush()
	assert.NoError(t, err)
}

func TestConsoleWriter_WriteAssessment_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(WithOutput(&buf), WithColor(false))

	a := createTestAssessment(t, nil)
	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
		Reasons:  []string{"No findings detected"},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "VerdictSec Security Assessment")
	assert.Contains(t, output, "Target:")
	assert.Contains(t, output, "Summary")
	assert.Contains(t, output, "PASS")
}

func TestConsoleWriter_WriteAssessment_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(WithOutput(&buf), WithColor(false))

	findings := []*finding.Finding{
		createTestConsoleFinding("G101", "main.go", 10, finding.SeverityCritical),
		createTestConsoleFinding("G104", "util.go", 20, finding.SeverityHigh),
		createTestConsoleFinding("G201", "db.go", 30, finding.SeverityMedium),
		createTestConsoleFinding("G304", "io.go", 40, finding.SeverityLow),
	}

	a := createTestAssessment(t, findings)
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		Reasons:     []string{"Critical findings detected"},
		NewFindings: findings,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Findings")
	assert.Contains(t, output, "[CRITICAL]")
	assert.Contains(t, output, "[HIGH]")
	assert.Contains(t, output, "[MEDIUM]")
	assert.Contains(t, output, "[LOW]")
	assert.Contains(t, output, "main.go:10")
	assert.Contains(t, output, "FAIL")
}

func TestConsoleWriter_WriteAssessment_Quiet(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(
		WithOutput(&buf),
		WithColor(false),
		WithVerbosity(ports.VerbosityQuiet),
	)

	findings := []*finding.Finding{
		createTestConsoleFinding("G101", "main.go", 10, finding.SeverityCritical),
	}

	a := createTestAssessment(t, findings)
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: findings,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	// Should have header and summary but not findings details
	assert.Contains(t, output, "VerdictSec")
	assert.NotContains(t, output, "[CRITICAL]") // Findings not shown in quiet mode
}

func TestConsoleWriter_WriteAssessment_Verbose(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(
		WithOutput(&buf),
		WithColor(false),
		WithVerbosity(ports.VerbosityVerbose),
	)

	// Create finding with metadata
	loc := finding.NewLocation("secret.go", 10, 1, 10, 80)
	f := finding.NewFinding(
		finding.FindingTypeSecret,
		"gitleaks",
		"generic-api-key",
		"Hardcoded API key detected",
		finding.SeverityHigh,
		loc,
		finding.WithDescription("A hardcoded API key was found in the source code"),
		finding.WithCWE("CWE-798"),
		finding.WithMetadata("secret", "api_key=12345"),
	)

	a := createTestAssessment(t, []*finding.Finding{f})
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Assessment ID:")
	assert.Contains(t, output, "Description:")
	assert.Contains(t, output, "CWE:")
	assert.Contains(t, output, "Secret:")
}

func TestConsoleWriter_WriteSummary(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(WithOutput(&buf), WithColor(false))

	findings := []*finding.Finding{
		createTestConsoleFinding("G101", "main.go", 10, finding.SeverityCritical),
	}

	a := createTestAssessment(t, findings)
	result := services.EvaluationResult{
		Decision:    assessment.DecisionWarn,
		Reasons:     []string{"High severity findings detected"},
		NewFindings: findings,
	}

	err := w.WriteSummary(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Summary")
	assert.Contains(t, output, "Total Findings:")
	assert.Contains(t, output, "WARN")
}

func TestConsoleWriter_WriteAssessment_BaselineAndSuppressed(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(WithOutput(&buf), WithColor(false))

	existing := createTestConsoleFinding("G101", "existing.go", 10, finding.SeverityMedium)
	suppressed := createTestConsoleFinding("G104", "suppressed.go", 20, finding.SeverityLow)
	newFinding := createTestConsoleFinding("G201", "new.go", 30, finding.SeverityHigh)

	allFindings := []*finding.Finding{existing, suppressed, newFinding}
	a := createTestAssessment(t, allFindings)

	result := services.EvaluationResult{
		Decision:    assessment.DecisionWarn,
		NewFindings: []*finding.Finding{newFinding},
		Existing:    []*finding.Finding{existing},
		Suppressed:  []*finding.Finding{suppressed},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "(baseline)")
	assert.Contains(t, output, "(suppressed)")
	assert.Contains(t, output, "New: 1")
	assert.Contains(t, output, "Baseline: 1")
	assert.Contains(t, output, "Suppressed: 1")
}

func TestConsoleWriter_DecisionColors(t *testing.T) {
	tests := []struct {
		name     string
		decision assessment.Decision
		expected string
	}{
		{"pass", assessment.DecisionPass, "PASS"},
		{"warn", assessment.DecisionWarn, "WARN"},
		{"fail", assessment.DecisionFail, "FAIL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewConsoleWriter(WithOutput(&buf), WithColor(false))

			a := createTestAssessment(t, nil)
			result := services.EvaluationResult{
				Decision: tt.decision,
			}

			err := w.WriteSummary(a, result)
			require.NoError(t, err)

			output := buf.String()
			assert.Contains(t, output, tt.expected)
		})
	}
}

func TestConsoleWriter_SeverityString(t *testing.T) {
	w := NewConsoleWriter(WithColor(false))

	tests := []struct {
		severity finding.Severity
		expected string
	}{
		{finding.SeverityCritical, "[CRITICAL]"},
		{finding.SeverityHigh, "[HIGH]"},
		{finding.SeverityMedium, "[MEDIUM]"},
		{finding.SeverityLow, "[LOW]"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := w.severityString(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConsoleWriter_SeverityString_Unknown(t *testing.T) {
	w := NewConsoleWriter(WithColor(false))

	// Invalid severity value
	result := w.severityString(finding.Severity(99))
	assert.Equal(t, "[UNKNOWN]", result)
}

func TestConsoleWriter_ColorsEnabled(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(WithOutput(&buf), WithColor(true))

	findings := []*finding.Finding{
		createTestConsoleFinding("G101", "main.go", 10, finding.SeverityCritical),
	}

	a := createTestAssessment(t, findings)
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: findings,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	// With colors enabled, the output should contain ANSI escape codes
	// The content should still be there
	assert.Contains(t, output, "VerdictSec")
}

func TestConsoleWriter_VerboseWithCVE(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(
		WithOutput(&buf),
		WithColor(false),
		WithVerbosity(ports.VerbosityVerbose),
	)

	loc := finding.NewLocation("deps.go", 10, 1, 10, 80)
	f := finding.NewFinding(
		finding.FindingTypeVuln,
		"govulncheck",
		"GO-2024-1234",
		"Vulnerable dependency",
		finding.SeverityCritical,
		loc,
		finding.WithCVE("CVE-2024-1234"),
		finding.WithFixVersion("v1.2.3"),
	)

	a := createTestAssessment(t, []*finding.Finding{f})
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "CVE:")
	assert.Contains(t, output, "CVE-2024-1234")
	assert.Contains(t, output, "Fix Version:")
	assert.Contains(t, output, "v1.2.3")
}

func TestIsInSlice(t *testing.T) {
	f1 := createTestConsoleFinding("G101", "a.go", 10, finding.SeverityHigh)
	f2 := createTestConsoleFinding("G102", "b.go", 20, finding.SeverityMedium)
	f3 := createTestConsoleFinding("G103", "c.go", 30, finding.SeverityLow)

	slice := []*finding.Finding{f1, f2}

	assert.True(t, isInSlice(f1, slice))
	assert.True(t, isInSlice(f2, slice))
	assert.False(t, isInSlice(f3, slice))
}

func TestIsInSlice_Empty(t *testing.T) {
	f := createTestConsoleFinding("G101", "a.go", 10, finding.SeverityHigh)

	assert.False(t, isInSlice(f, nil))
	assert.False(t, isInSlice(f, []*finding.Finding{}))
}

func TestConsoleWriter_DebugVerbosity(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(
		WithOutput(&buf),
		WithColor(false),
		WithVerbosity(ports.VerbosityDebug),
	)

	findings := []*finding.Finding{
		createTestConsoleFinding("G101", "main.go", 10, finding.SeverityHigh),
	}

	a := createTestAssessment(t, findings)
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: findings,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Assessment ID:")
}

func TestConsoleWriter_MultipleReasons(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(
		WithOutput(&buf),
		WithColor(false),
	)

	a := createTestAssessment(t, nil)
	result := services.EvaluationResult{
		Decision: assessment.DecisionFail,
		Reasons: []string{
			"Critical findings detected",
			"High findings exceed threshold",
			"New findings in sensitive files",
		},
	}

	err := w.WriteSummary(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Critical findings detected")
	assert.Contains(t, output, "High findings exceed threshold")
	assert.Contains(t, output, "New findings in sensitive files")
}

// Helper functions

func createTestAssessment(t *testing.T, findings []*finding.Finding) *assessment.Assessment {
	t.Helper()

	a := assessment.NewAssessment("./test-project")

	// Add findings if provided
	for _, f := range findings {
		a.AddFinding(f)
	}

	// Complete the assessment
	a.Complete()

	return a
}

func createTestConsoleFinding(ruleID, file string, line int, severity finding.Severity) *finding.Finding {
	loc := finding.NewLocation(file, line, 1, line, 80)
	return finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		ruleID,
		"Test finding: "+ruleID,
		severity,
		loc,
	)
}

// Test that console writer handles findings without metadata
func TestConsoleWriter_FindingWithoutMetadata(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(
		WithOutput(&buf),
		WithColor(false),
		WithVerbosity(ports.VerbosityVerbose),
	)

	// Finding without any metadata set
	loc := finding.NewLocation("plain.go", 10, 1, 10, 80)
	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Plain finding",
		finding.SeverityMedium,
		loc,
	)

	a := createTestAssessment(t, []*finding.Finding{f})
	result := services.EvaluationResult{
		Decision:    assessment.DecisionWarn,
		NewFindings: []*finding.Finding{f},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	// Should not crash, should still produce output
	output := buf.String()
	assert.Contains(t, output, "Plain finding")
}

// Test time formatting in header
func TestConsoleWriter_Duration(t *testing.T) {
	var buf bytes.Buffer
	w := NewConsoleWriter(WithOutput(&buf), WithColor(false))

	a := assessment.NewAssessment("./project")
	time.Sleep(10 * time.Millisecond) // Small delay
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Duration:")
}

// Test that interface is properly implemented
func TestConsoleWriter_ImplementsInterface(t *testing.T) {
	w := NewConsoleWriter()

	// This will fail at compile time if not implemented
	var _ ports.ConsoleWriter = w
}
