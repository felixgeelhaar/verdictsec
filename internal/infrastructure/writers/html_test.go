package writers

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTMLWriter(t *testing.T) {
	writer := NewHTMLWriter()
	assert.NotNil(t, writer)
	assert.Equal(t, "VerdictSec Security Report", writer.title)
	assert.True(t, writer.includeStyles)
}

func TestNewHTMLWriter_WithOptions(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(
		WithHTMLOutput(&buf),
		WithHTMLTitle("Custom Report"),
		WithHTMLStyles(false),
	)

	assert.NotNil(t, writer)
	assert.Equal(t, &buf, writer.out)
	assert.Equal(t, "Custom Report", writer.title)
	assert.False(t, writer.includeStyles)
}

func TestHTMLWriter_SetOutput(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter()
	writer.SetOutput(&buf)
	assert.Equal(t, &buf, writer.out)
}

func TestHTMLWriter_WriteAssessment_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

	a := assessment.NewAssessment("test-target")
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()

	// Check HTML structure
	assert.Contains(t, output, "<!DOCTYPE html>")
	assert.Contains(t, output, "VerdictSec Security Report")
	assert.Contains(t, output, "test-target")
	assert.Contains(t, output, "PASS")
	assert.Contains(t, output, "No security findings detected")
}

func TestHTMLWriter_WriteAssessment_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

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

	// Check finding is present
	assert.Contains(t, output, "New Findings")
	assert.Contains(t, output, "Use of weak cryptographic primitive")
	assert.Contains(t, output, "G401")
	assert.Contains(t, output, "gosec")
	assert.Contains(t, output, "pkg/handler/auth.go")
	assert.Contains(t, output, "CWE-327")
	assert.Contains(t, output, "HIGH")
}

func TestHTMLWriter_WriteAssessment_SuppressedFinding(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

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

	output := buf.String()
	assert.Contains(t, output, "Suppressed Findings")
	assert.Contains(t, output, "Hardcoded credentials")
}

func TestHTMLWriter_WriteAssessment_BaselineFinding(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

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

	output := buf.String()
	assert.Contains(t, output, "Baseline Findings")
	assert.Contains(t, output, "Hardcoded credentials")
}

func TestHTMLWriter_WriteAssessment_WithCVE(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

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
	assert.Contains(t, output, "CVE-2023-1234")
}

func TestHTMLWriter_DecisionClass(t *testing.T) {
	writer := NewHTMLWriter()

	tests := []struct {
		decision assessment.Decision
		expected string
	}{
		{assessment.DecisionPass, "pass"},
		{assessment.DecisionWarn, "warn"},
		{assessment.DecisionFail, "fail"},
	}

	for _, tt := range tests {
		t.Run(tt.decision.String(), func(t *testing.T) {
			result := writer.decisionClass(tt.decision)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTMLWriter_SeverityClass(t *testing.T) {
	writer := NewHTMLWriter()

	tests := []struct {
		severity finding.Severity
		expected string
	}{
		{finding.SeverityCritical, "critical"},
		{finding.SeverityHigh, "high"},
		{finding.SeverityMedium, "medium"},
		{finding.SeverityLow, "low"},
		{finding.SeverityUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			result := writer.severityClass(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTMLWriter_WriteProgress(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

	err := writer.WriteProgress("Scanning files...")
	assert.NoError(t, err)
	// No output for HTML progress
	assert.Empty(t, buf.String())
}

func TestHTMLWriter_WriteError(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

	err := writer.WriteError(nil)
	assert.NoError(t, err)
	// No output for HTML errors
	assert.Empty(t, buf.String())
}

func TestHTMLWriter_Flush(t *testing.T) {
	writer := NewHTMLWriter()
	err := writer.Flush()
	assert.NoError(t, err)
}

func TestHTMLWriter_Close(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))
	err := writer.Close()
	assert.NoError(t, err)
}

func TestHTMLWriter_NoStyles(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(
		WithHTMLOutput(&buf),
		WithHTMLStyles(false),
	)

	a := assessment.NewAssessment("test-target")
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()

	// Check styles are not included
	assert.NotContains(t, output, "<style>")
}

func TestHTMLWriter_CustomTitle(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(
		WithHTMLOutput(&buf),
		WithHTMLTitle("My Custom Report"),
	)

	a := assessment.NewAssessment("test-target")
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "My Custom Report")
}

func TestHTMLWriter_SeverityCounts(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

	a := assessment.NewAssessment("test-target")

	// Add findings of different severities
	locs := []finding.Location{
		finding.NewLocation("file1.go", 1, 1, 1, 10),
		finding.NewLocation("file2.go", 2, 1, 2, 10),
		finding.NewLocation("file3.go", 3, 1, 3, 10),
		finding.NewLocation("file4.go", 4, 1, 4, 10),
	}

	findings := []*finding.Finding{
		finding.NewFinding(finding.FindingTypeSAST, "gosec", "G101", "Critical", finding.SeverityCritical, locs[0]),
		finding.NewFinding(finding.FindingTypeSAST, "gosec", "G102", "High", finding.SeverityHigh, locs[1]),
		finding.NewFinding(finding.FindingTypeSAST, "gosec", "G103", "Medium", finding.SeverityMedium, locs[2]),
		finding.NewFinding(finding.FindingTypeSAST, "gosec", "G104", "Low", finding.SeverityLow, locs[3]),
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

	// Check severity counts are displayed
	assert.Contains(t, output, "Critical")
	assert.Contains(t, output, "High")
	assert.Contains(t, output, "Medium")
	assert.Contains(t, output, "Low")
}

func TestHTMLWriter_EngineRuns(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

	a := assessment.NewAssessment("test-target")
	run := assessment.NewEngineRun("gosec", "2.18.0")
	run.Complete(3)
	a.AddEngineRun(run)
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()

	// Check engine runs are displayed
	assert.Contains(t, output, "Engine Runs")
	assert.Contains(t, output, "gosec")
	assert.Contains(t, output, "3 findings")
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{500 * time.Millisecond, "500ms"},
		{1 * time.Second, "1s"},
		{1500 * time.Millisecond, "1.5s"},
		{65 * time.Second, "1m5s"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatDuration(tt.duration)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFactory_Create_HTML(t *testing.T) {
	f := NewFactory()

	config := ports.OutputConfig{}

	writer, err := f.Create(ports.OutputFormatHTML, config)

	require.NoError(t, err)
	assert.NotNil(t, writer)

	// Should be an HTML writer
	_, ok := writer.(*HTMLWriter)
	assert.True(t, ok)
}

func TestFactory_CreateToFile_HTML(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := strings.Join([]string{tmpDir, "output.html"}, "/")

	f := NewFactory()
	config := ports.OutputConfig{}

	writer, err := f.CreateToFile(ports.OutputFormatHTML, filePath, config)

	require.NoError(t, err)
	assert.NotNil(t, writer)

	// Close the writer
	if closer, ok := writer.(interface{ Close() error }); ok {
		err = closer.Close()
		require.NoError(t, err)
	}
}

func TestFileHTMLWriter_Close(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := strings.Join([]string{tmpDir, "output.html"}, "/")

	f := NewFactory()
	config := ports.OutputConfig{}

	writer, err := f.CreateToFile(ports.OutputFormatHTML, filePath, config)
	require.NoError(t, err)

	// Type assert to get the fileHTMLWriter
	htmlWriter, ok := writer.(*fileHTMLWriter)
	require.True(t, ok)

	err = htmlWriter.Close()
	require.NoError(t, err)
}

func TestHTMLWriter_ImplementsInterface(t *testing.T) {
	writer := NewHTMLWriter()
	var _ ports.ArtifactWriter = writer
}

func TestHTMLWriter_WriteSummary(t *testing.T) {
	var buf bytes.Buffer
	writer := NewHTMLWriter(WithHTMLOutput(&buf))

	a := assessment.NewAssessment("test-target")
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := writer.WriteSummary(a, result)
	require.NoError(t, err)

	// Should produce same output as WriteAssessment
	assert.Contains(t, buf.String(), "<!DOCTYPE html>")
}
