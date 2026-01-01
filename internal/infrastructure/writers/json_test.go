package writers

import (
	"bytes"
	"encoding/json"
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

func TestNewJSONWriter(t *testing.T) {
	w := NewJSONWriter()

	assert.NotNil(t, w)
	assert.NotNil(t, w.out)
	assert.False(t, w.pretty)
	assert.NotNil(t, w.redactor)
}

func TestNewJSONWriter_WithOptions(t *testing.T) {
	var buf bytes.Buffer

	w := NewJSONWriter(
		WithJSONOutput(&buf),
		WithPrettyPrint(true),
	)

	assert.Equal(t, &buf, w.out)
	assert.True(t, w.pretty)
}

func TestJSONWriter_SetOutput(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter()

	w.SetOutput(&buf)
	assert.Equal(t, &buf, w.out)
}

func TestJSONWriter_SetPretty(t *testing.T) {
	w := NewJSONWriter()

	w.SetPretty(true)
	assert.True(t, w.pretty)

	w.SetPretty(false)
	assert.False(t, w.pretty)
}

func TestJSONWriter_Close_NoCloser(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	err := w.Close()
	assert.NoError(t, err)
}

type mockCloser struct {
	bytes.Buffer
	closed bool
}

func (m *mockCloser) Close() error {
	m.closed = true
	return nil
}

func TestJSONWriter_Close_WithCloser(t *testing.T) {
	mock := &mockCloser{}
	w := NewJSONWriter(WithJSONOutput(mock))

	err := w.Close()
	assert.NoError(t, err)
	assert.True(t, mock.closed)
}

func TestJSONWriter_Flush(t *testing.T) {
	w := NewJSONWriter()

	err := w.Flush()
	assert.NoError(t, err)
}

func TestJSONWriter_WriteProgress(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	err := w.WriteProgress("Scanning files...")
	require.NoError(t, err)

	var progress JSONProgress
	err = json.Unmarshal(buf.Bytes(), &progress)
	require.NoError(t, err)

	assert.Equal(t, "progress", progress.Type)
	assert.Equal(t, "Scanning files...", progress.Message)
	assert.False(t, progress.Timestamp.IsZero())
}

func TestJSONWriter_WriteError(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	testErr := errors.New("something went wrong")
	err := w.WriteError(testErr)
	require.NoError(t, err)

	var errOutput JSONError
	err = json.Unmarshal(buf.Bytes(), &errOutput)
	require.NoError(t, err)

	assert.Equal(t, "error", errOutput.Type)
	assert.Equal(t, "something went wrong", errOutput.Message)
	assert.False(t, errOutput.Timestamp.IsZero())
}

func TestJSONWriter_WriteAssessment_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	a := createTestJSONAssessment(t, nil)
	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
		Reasons:  []string{"No findings detected"},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, "1", output.Version)
	assert.NotEmpty(t, output.AssessmentID)
	assert.Equal(t, "./test-project", output.Target)
	assert.Empty(t, output.Findings)
	assert.Equal(t, "PASS", output.Decision.Result)
	assert.Contains(t, output.Decision.Reasons, "No findings detected")
}

func TestJSONWriter_WriteAssessment_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	findings := []*finding.Finding{
		createTestJSONFinding("G101", "main.go", 10, finding.SeverityCritical),
		createTestJSONFinding("G104", "util.go", 20, finding.SeverityHigh),
	}

	a := createTestJSONAssessment(t, findings)
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		Reasons:     []string{"Critical findings detected"},
		NewFindings: findings,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Len(t, output.Findings, 2)
	assert.Equal(t, "FAIL", output.Decision.Result)
	assert.Equal(t, 2, output.Summary.Total)
	assert.Equal(t, 2, output.Summary.NewCount)
}

func TestJSONWriter_WriteAssessment_PrettyPrint(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(
		WithJSONOutput(&buf),
		WithPrettyPrint(true),
	)

	a := createTestJSONAssessment(t, nil)
	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	output := buf.String()
	// Pretty print should have newlines and indentation
	assert.Contains(t, output, "\n")
	assert.Contains(t, output, "  ")
}

func TestJSONWriter_WriteSummary(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	findings := []*finding.Finding{
		createTestJSONFinding("G101", "main.go", 10, finding.SeverityCritical),
	}

	a := createTestJSONAssessment(t, findings)
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: findings,
	}

	err := w.WriteSummary(a, result)
	require.NoError(t, err)

	var summary JSONSummary
	err = json.Unmarshal(buf.Bytes(), &summary)
	require.NoError(t, err)

	assert.Equal(t, "./test-project", summary.Target)
	assert.Equal(t, "FAIL", summary.Decision)
	assert.Equal(t, 1, summary.TotalCount)
	assert.Equal(t, 1, summary.NewCount)
}

func TestJSONWriter_WriteAssessment_BaselineAndSuppressed(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	existing := createTestJSONFinding("G101", "existing.go", 10, finding.SeverityMedium)
	suppressed := createTestJSONFinding("G104", "suppressed.go", 20, finding.SeverityLow)
	newFinding := createTestJSONFinding("G201", "new.go", 30, finding.SeverityHigh)

	allFindings := []*finding.Finding{existing, suppressed, newFinding}
	a := createTestJSONAssessment(t, allFindings)

	result := services.EvaluationResult{
		Decision:    assessment.DecisionWarn,
		NewFindings: []*finding.Finding{newFinding},
		Existing:    []*finding.Finding{existing},
		Suppressed:  []*finding.Finding{suppressed},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	// Check status assignments
	statusCounts := map[string]int{}
	for _, f := range output.Findings {
		statusCounts[f.Status]++
	}

	assert.Equal(t, 1, statusCounts["new"])
	assert.Equal(t, 1, statusCounts["baseline"])
	assert.Equal(t, 1, statusCounts["suppressed"])

	assert.Equal(t, 1, output.Summary.NewCount)
	assert.Equal(t, 1, output.Summary.ExistingCount)
	assert.Equal(t, 1, output.Summary.SuppressedCount)
}

func TestJSONWriter_WriteAssessment_SeverityCounts(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	findings := []*finding.Finding{
		createTestJSONFinding("G001", "a.go", 10, finding.SeverityCritical),
		createTestJSONFinding("G002", "b.go", 20, finding.SeverityCritical),
		createTestJSONFinding("G003", "c.go", 30, finding.SeverityHigh),
		createTestJSONFinding("G004", "d.go", 40, finding.SeverityMedium),
		createTestJSONFinding("G005", "e.go", 50, finding.SeverityLow),
		createTestJSONFinding("G006", "f.go", 60, finding.SeverityLow),
		createTestJSONFinding("G007", "g.go", 70, finding.SeverityLow),
	}

	a := createTestJSONAssessment(t, findings)
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: findings,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Equal(t, 2, output.Summary.BySeverity["critical"])
	assert.Equal(t, 1, output.Summary.BySeverity["high"])
	assert.Equal(t, 1, output.Summary.BySeverity["medium"])
	assert.Equal(t, 3, output.Summary.BySeverity["low"])
}

func TestJSONWriter_WriteAssessment_WithMetadata(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	loc := finding.NewLocation("secret.go", 10, 1, 10, 80)
	f := finding.NewFinding(
		finding.FindingTypeSecret,
		"gitleaks",
		"generic-api-key",
		"Hardcoded API key",
		finding.SeverityHigh,
		loc,
		finding.WithMetadata("secret", "AKIAIOSFODNN7EXAMPLE"),
		finding.WithMetadata("normal", "not-sensitive"),
	)

	a := createTestJSONAssessment(t, []*finding.Finding{f})
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	// Check that sensitive metadata is redacted
	metadata := output.Findings[0].Metadata
	assert.NotNil(t, metadata)

	// The secret key should be redacted (contains partial display or placeholder)
	secret := metadata["secret"].(string)
	assert.NotEqual(t, "AKIAIOSFODNN7EXAMPLE", secret)
	// Should contain partial redaction or placeholder
	assert.True(t, len(secret) > 0)
}

func TestJSONWriter_WriteAssessment_WithEngineRuns(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	a := assessment.NewAssessment("./project")

	// Add a successful engine run
	run := assessment.NewEngineRun("gosec", "2.18.0")
	run.Complete(3)
	a.AddEngineRun(run)

	// Add a failed engine run
	failedRun := assessment.NewEngineRun("gitleaks", "8.18.0")
	failedRun.Fail(errors.New("engine failed"))
	a.AddEngineRun(failedRun)

	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Len(t, output.EngineRuns, 2)

	// Find the gosec run
	var gosecRun, gitleaksRun JSONEngineRun
	for _, run := range output.EngineRuns {
		if run.EngineID == "gosec" {
			gosecRun = run
		} else if run.EngineID == "gitleaks" {
			gitleaksRun = run
		}
	}

	assert.Equal(t, "gosec", gosecRun.EngineID)
	assert.Equal(t, "2.18.0", gosecRun.Version)
	assert.True(t, gosecRun.Success)
	assert.Equal(t, 3, gosecRun.FindingCount)
	assert.Empty(t, gosecRun.Error)

	assert.Equal(t, "gitleaks", gitleaksRun.EngineID)
	assert.False(t, gitleaksRun.Success)
	assert.Equal(t, "engine failed", gitleaksRun.Error)
}

func TestJSONWriter_WriteAssessment_WithCWEAndCVE(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	loc := finding.NewLocation("vuln.go", 10, 1, 10, 80)
	f := finding.NewFinding(
		finding.FindingTypeVuln,
		"govulncheck",
		"GO-2024-1234",
		"Vulnerable dependency",
		finding.SeverityCritical,
		loc,
		finding.WithCWE("CWE-79"),
		finding.WithCVE("CVE-2024-1234"),
		finding.WithFixVersion("v1.2.3"),
		finding.WithDescription("A critical vulnerability"),
	)

	a := createTestJSONAssessment(t, []*finding.Finding{f})
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Len(t, output.Findings, 1)
	finding := output.Findings[0]
	assert.Equal(t, "CWE-79", finding.CWEID)
	assert.Equal(t, "CVE-2024-1234", finding.CVEID)
	assert.Equal(t, "v1.2.3", finding.FixVersion)
	assert.Equal(t, "A critical vulnerability", finding.Description)
}

func TestJSONWriter_FindingFields(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	loc := finding.NewLocation("test.go", 10, 5, 12, 80)
	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Test finding",
		finding.SeverityHigh,
		loc,
		finding.WithConfidence(finding.ConfidenceHigh),
	)

	a := createTestJSONAssessment(t, []*finding.Finding{f})
	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.Len(t, output.Findings, 1)
	jf := output.Findings[0]

	assert.NotEmpty(t, jf.ID)
	assert.Equal(t, "sast", jf.Type)
	assert.Equal(t, "gosec", jf.EngineID)
	assert.Equal(t, "G101", jf.RuleID)
	assert.Equal(t, "Test finding", jf.Title)
	assert.Equal(t, "HIGH", jf.Severity)
	assert.Equal(t, "HIGH", jf.Confidence)
	assert.NotEmpty(t, jf.Fingerprint)

	assert.Equal(t, "test.go", jf.Location.File)
	assert.Equal(t, 10, jf.Location.Line)
	assert.Equal(t, 5, jf.Location.Column)
	assert.Equal(t, 12, jf.Location.EndLine)
	assert.Equal(t, 80, jf.Location.EndColumn)
}

func TestJSONWriter_ImplementsInterface(t *testing.T) {
	w := NewJSONWriter()

	var _ ports.JSONWriter = w
}

func TestJSONOutput_Duration(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	a := assessment.NewAssessment("./project")
	time.Sleep(10 * time.Millisecond)
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	assert.NotEmpty(t, output.Duration)
	assert.False(t, output.StartedAt.IsZero())
	assert.False(t, output.CompletedAt.IsZero())
}

func TestJSONSummary_Duration(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	a := assessment.NewAssessment("./project")
	time.Sleep(5 * time.Millisecond)
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := w.WriteSummary(a, result)
	require.NoError(t, err)

	var summary JSONSummary
	err = json.Unmarshal(buf.Bytes(), &summary)
	require.NoError(t, err)

	assert.NotEmpty(t, summary.Duration)
}

func TestJSONWriter_NoMetadata(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(WithJSONOutput(&buf))

	// Finding without any metadata
	loc := finding.NewLocation("plain.go", 10, 1, 10, 80)
	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Plain finding",
		finding.SeverityMedium,
		loc,
	)

	a := createTestJSONAssessment(t, []*finding.Finding{f})
	result := services.EvaluationResult{
		Decision:    assessment.DecisionWarn,
		NewFindings: []*finding.Finding{f},
	}

	err := w.WriteAssessment(a, result)
	require.NoError(t, err)

	var output JSONOutput
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)

	// Metadata should be nil or empty when not set
	assert.Nil(t, output.Findings[0].Metadata)
}

// Helper functions

func createTestJSONAssessment(t *testing.T, findings []*finding.Finding) *assessment.Assessment {
	t.Helper()

	a := assessment.NewAssessment("./test-project")

	for _, f := range findings {
		a.AddFinding(f)
	}

	a.Complete()

	return a
}

func createTestJSONFinding(ruleID, file string, line int, severity finding.Severity) *finding.Finding {
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
