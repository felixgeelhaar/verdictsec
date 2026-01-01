package writers

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGitHubActionsWriter(t *testing.T) {
	writer := NewGitHubActionsWriter()
	assert.NotNil(t, writer)
	assert.True(t, writer.groupFindings)
}

func TestNewGitHubActionsWriter_WithOptions(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(
		WithGitHubOutput(&buf),
		WithGroupFindings(false),
	)

	assert.NotNil(t, writer)
	assert.Equal(t, &buf, writer.out)
	assert.False(t, writer.groupFindings)
}

func TestGitHubActionsWriter_SetOutput(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter()
	writer.SetOutput(&buf)
	assert.Equal(t, &buf, writer.out)
}

func TestGitHubActionsWriter_WriteAssessment_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(WithGitHubOutput(&buf))

	a := assessment.NewAssessment("test-target")
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	// No output for no findings
	assert.Empty(t, buf.String())
}

func TestGitHubActionsWriter_WriteAssessment_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(WithGitHubOutput(&buf))

	a := assessment.NewAssessment("test-target")

	loc := finding.NewLocation("pkg/handler/auth.go", 42, 10, 42, 50)
	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G401",
		"Use of weak cryptographic primitive",
		finding.SeverityHigh,
		loc,
		finding.WithCWE("CWE-327"),
	)
	a.AddFinding(f)
	a.Complete()

	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()

	// Check for group markers
	assert.Contains(t, output, "::group::VerdictSec Security Findings")
	assert.Contains(t, output, "::endgroup::")

	// Check for annotation
	assert.Contains(t, output, "::error file=pkg/handler/auth.go")
	assert.Contains(t, output, "line=42")
	assert.Contains(t, output, "[gosec]")
	assert.Contains(t, output, "G401")
	assert.Contains(t, output, "(CWE-327)")
}

func TestGitHubActionsWriter_WriteAssessment_SuppressedFinding(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(WithGitHubOutput(&buf), WithGroupFindings(false))

	a := assessment.NewAssessment("test-target")

	loc := finding.NewLocation("file.go", 10, 1, 10, 20)
	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Hardcoded credentials",
		finding.SeverityCritical,
		loc,
	)
	a.AddFinding(f)
	a.Complete()

	result := services.EvaluationResult{
		Decision:   assessment.DecisionPass,
		Suppressed: []*finding.Finding{f},
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	// Suppressed findings should not appear in output
	output := buf.String()
	assert.NotContains(t, output, "G101")
	assert.NotContains(t, output, "Hardcoded credentials")
}

func TestGitHubActionsWriter_WriteAssessment_BaselineFinding(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(WithGitHubOutput(&buf))

	a := assessment.NewAssessment("test-target")

	loc := finding.NewLocation("file.go", 10, 1, 10, 20)
	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Hardcoded credentials",
		finding.SeverityCritical,
		loc,
	)
	a.AddFinding(f)
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionWarn,
		Existing: []*finding.Finding{f},
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	// Baseline findings should have [baseline] marker
	output := buf.String()
	assert.Contains(t, output, "[baseline]")
}

func TestGitHubActionsWriter_WriteAssessment_WithCVE(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(WithGitHubOutput(&buf))

	a := assessment.NewAssessment("test-target")

	loc := finding.NewLocation("go.mod", 5, 1, 5, 30)
	f := finding.NewFinding(
		finding.FindingTypeVuln,
		"govulncheck",
		"GO-2023-1234",
		"SQL injection vulnerability",
		finding.SeverityHigh,
		loc,
		finding.WithCVE("CVE-2023-1234"),
	)
	a.AddFinding(f)
	a.Complete()

	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "[CVE-2023-1234]")
}

func TestGitHubActionsWriter_SeverityToLevel(t *testing.T) {
	writer := NewGitHubActionsWriter()

	tests := []struct {
		severity finding.Severity
		expected string
	}{
		{finding.SeverityCritical, "error"},
		{finding.SeverityHigh, "error"},
		{finding.SeverityMedium, "warning"},
		{finding.SeverityLow, "notice"},
		{finding.SeverityUnknown, "notice"},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			result := writer.severityToLevel(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGitHubActionsWriter_WriteProgress(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(WithGitHubOutput(&buf))

	err := writer.WriteProgress("Scanning files...")
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "::debug::")
	assert.Contains(t, buf.String(), "Scanning files")
}

func TestGitHubActionsWriter_WriteError(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(WithGitHubOutput(&buf))

	err := writer.WriteError(errors.New("test error"))
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "::error::")
	assert.Contains(t, buf.String(), "test error")
}

func TestGitHubActionsWriter_Flush(t *testing.T) {
	writer := NewGitHubActionsWriter()
	err := writer.Flush()
	assert.NoError(t, err)
}

func TestGitHubActionsWriter_Close(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(WithGitHubOutput(&buf))
	err := writer.Close()
	assert.NoError(t, err)
}

func TestGitHubActionsWriter_NoGrouping(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(
		WithGitHubOutput(&buf),
		WithGroupFindings(false),
	)

	a := assessment.NewAssessment("test-target")

	loc := finding.NewLocation("file.go", 10, 1, 10, 20)
	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Test",
		finding.SeverityHigh,
		loc,
	)
	a.AddFinding(f)
	a.Complete()

	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()

	// No group markers when grouping is disabled
	assert.NotContains(t, output, "::group::")
	assert.NotContains(t, output, "::endgroup::")

	// But annotation should still be present
	assert.Contains(t, output, "::error file=file.go")
}

func TestGitHubActionsWriter_Summary(t *testing.T) {
	var buf bytes.Buffer
	writer := NewGitHubActionsWriter(WithGitHubOutput(&buf))

	a := assessment.NewAssessment("test-target")

	// Add findings of different severities
	locs := []finding.Location{
		finding.NewLocation("file1.go", 1, 1, 1, 10),
		finding.NewLocation("file2.go", 2, 1, 2, 10),
		finding.NewLocation("file3.go", 3, 1, 3, 10),
	}

	findings := []*finding.Finding{
		finding.NewFinding(finding.FindingTypeSAST, "gosec", "G101", "Critical", finding.SeverityCritical, locs[0]),
		finding.NewFinding(finding.FindingTypeSAST, "gosec", "G102", "High", finding.SeverityHigh, locs[1]),
		finding.NewFinding(finding.FindingTypeSAST, "gosec", "G103", "Medium", finding.SeverityMedium, locs[2]),
	}

	for _, f := range findings {
		a.AddFinding(f)
	}
	a.Complete()

	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: findings,
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()

	// Check summary line
	assert.Contains(t, output, "::error title=Security Scan Results::")
	assert.Contains(t, output, "3 findings")
	assert.Contains(t, output, "1 critical")
	assert.Contains(t, output, "1 high")
	assert.Contains(t, output, "1 medium")
}

func TestEscapeMessage(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with%percent", "with%25percent"},
		{"with\nnewline", "with%0Anewline"},
		{"with\rcarriage", "with%0Dcarriage"},
		{"with:colon", "with%3Acolon"},
		{"with,comma", "with%2Ccomma"},
		{"mixed%\n:\r,", "mixed%25%0A%3A%0D%2C"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := escapeMessage(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFactory_Create_GitHubActions(t *testing.T) {
	f := NewFactory()

	config := ports.OutputConfig{}

	writer, err := f.Create(ports.OutputFormatGitHubActions, config)

	require.NoError(t, err)
	assert.NotNil(t, writer)

	// Should be a GitHub Actions writer
	_, ok := writer.(*GitHubActionsWriter)
	assert.True(t, ok)
}

func TestFactory_CreateToFile_GitHubActions(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := strings.Join([]string{tmpDir, "output.txt"}, "/")

	f := NewFactory()
	config := ports.OutputConfig{}

	writer, err := f.CreateToFile(ports.OutputFormatGitHubActions, filePath, config)

	require.NoError(t, err)
	assert.NotNil(t, writer)

	// Close the writer
	if closer, ok := writer.(interface{ Close() error }); ok {
		err = closer.Close()
		require.NoError(t, err)
	}
}

func TestGitHubActionsWriter_ImplementsInterface(t *testing.T) {
	writer := NewGitHubActionsWriter()
	var _ ports.ArtifactWriter = writer
}
