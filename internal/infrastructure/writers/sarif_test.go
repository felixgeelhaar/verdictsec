package writers

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSARIFWriter(t *testing.T) {
	writer := NewSARIFWriter()
	assert.NotNil(t, writer)
	assert.Equal(t, "VerdictSec", writer.toolName)
	assert.Equal(t, "1.0.0", writer.toolVer)
}

func TestNewSARIFWriter_WithOptions(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(
		WithSARIFOutput(&buf),
		WithToolInfo("CustomTool", "2.0.0"),
	)

	assert.NotNil(t, writer)
	assert.Equal(t, "CustomTool", writer.toolName)
	assert.Equal(t, "2.0.0", writer.toolVer)
	assert.Equal(t, &buf, writer.out)
}

func TestSARIFWriter_SetOutput(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter()
	writer.SetOutput(&buf)
	assert.Equal(t, &buf, writer.out)
}

func TestSARIFWriter_WriteAssessment_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))

	a := assessment.NewAssessment("test-target")
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	// Parse output
	var sarif SARIFLog
	err = json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)

	assert.Equal(t, SARIFVersion, sarif.Version)
	assert.Equal(t, SARIFSchema, sarif.Schema)
	assert.Len(t, sarif.Runs, 1)
	assert.Empty(t, sarif.Runs[0].Results)
	assert.Equal(t, "VerdictSec", sarif.Runs[0].Tool.Driver.Name)
}

func TestSARIFWriter_WriteAssessment_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))

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
		finding.WithConfidence(finding.ConfidenceHigh),
	)
	a.AddFinding(f)
	a.Complete()

	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	// Parse output
	var sarif SARIFLog
	err = json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)

	assert.Len(t, sarif.Runs[0].Results, 1)
	assert.Len(t, sarif.Runs[0].Tool.Driver.Rules, 1)

	// Check result
	res := sarif.Runs[0].Results[0]
	assert.Equal(t, "gosec/G401", res.RuleID)
	assert.Equal(t, "error", res.Level)
	assert.Equal(t, "Use of weak cryptographic primitive", res.Message.Text)
	assert.Equal(t, "new", res.BaselineState)

	// Check location
	assert.Len(t, res.Locations, 1)
	assert.Equal(t, "pkg/handler/auth.go", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 42, res.Locations[0].PhysicalLocation.Region.StartLine)

	// Check rule
	rule := sarif.Runs[0].Tool.Driver.Rules[0]
	assert.Equal(t, "gosec/G401", rule.ID)
	assert.Equal(t, "https://cwe.mitre.org/data/definitions/327.html", rule.HelpURI)
	assert.Contains(t, rule.Properties.Tags, "CWE-327")
}

func TestSARIFWriter_WriteAssessment_SuppressedFinding(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))

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

	var sarif SARIFLog
	err = json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)

	res := sarif.Runs[0].Results[0]
	assert.Len(t, res.Suppressions, 1)
	assert.Equal(t, "inSource", res.Suppressions[0].Kind)
}

func TestSARIFWriter_WriteAssessment_BaselineFinding(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))

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

	var sarif SARIFLog
	err = json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)

	res := sarif.Runs[0].Results[0]
	assert.Equal(t, "unchanged", res.BaselineState)
}

func TestSARIFWriter_SeverityToLevel(t *testing.T) {
	writer := NewSARIFWriter()

	tests := []struct {
		severity finding.Severity
		expected string
	}{
		{finding.SeverityCritical, "error"},
		{finding.SeverityHigh, "error"},
		{finding.SeverityMedium, "warning"},
		{finding.SeverityLow, "note"},
		{finding.SeverityUnknown, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			result := writer.severityToLevel(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSARIFWriter_SeverityToScore(t *testing.T) {
	writer := NewSARIFWriter()

	tests := []struct {
		severity finding.Severity
		expected string
	}{
		{finding.SeverityCritical, "9.0"},
		{finding.SeverityHigh, "7.0"},
		{finding.SeverityMedium, "5.0"},
		{finding.SeverityLow, "3.0"},
		{finding.SeverityUnknown, "0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			result := writer.severityToScore(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSARIFWriter_ConfidenceToPrecision(t *testing.T) {
	writer := NewSARIFWriter()

	tests := []struct {
		confidence finding.Confidence
		expected   string
	}{
		{finding.ConfidenceHigh, "high"},
		{finding.ConfidenceMedium, "medium"},
		{finding.ConfidenceLow, "low"},
		{finding.ConfidenceUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.confidence.String(), func(t *testing.T) {
			result := writer.confidenceToPrecision(tt.confidence)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSARIFWriter_BuildTags(t *testing.T) {
	writer := NewSARIFWriter()

	tests := []struct {
		name      string
		findingFn func() *finding.Finding
		expected  []string
	}{
		{
			name: "SAST finding",
			findingFn: func() *finding.Finding {
				return finding.NewFinding(
					finding.FindingTypeSAST,
					"gosec",
					"G101",
					"Test",
					finding.SeverityHigh,
					finding.NewLocation("file.go", 1, 1, 1, 10),
				)
			},
			expected: []string{"security", "static-analysis", "code-quality"},
		},
		{
			name: "Vulnerability finding",
			findingFn: func() *finding.Finding {
				return finding.NewFinding(
					finding.FindingTypeVuln,
					"govulncheck",
					"GO-2023-1234",
					"Test",
					finding.SeverityHigh,
					finding.NewLocation("go.mod", 1, 1, 1, 10),
				)
			},
			expected: []string{"security", "vulnerability", "dependency"},
		},
		{
			name: "Secret finding",
			findingFn: func() *finding.Finding {
				return finding.NewFinding(
					finding.FindingTypeSecret,
					"gitleaks",
					"aws-access-key",
					"Test",
					finding.SeverityCritical,
					finding.NewLocation("config.yaml", 5, 1, 5, 40),
				)
			},
			expected: []string{"security", "secret", "credential"},
		},
		{
			name: "Finding with CWE",
			findingFn: func() *finding.Finding {
				return finding.NewFinding(
					finding.FindingTypeSAST,
					"gosec",
					"G401",
					"Test",
					finding.SeverityHigh,
					finding.NewLocation("file.go", 1, 1, 1, 10),
					finding.WithCWE("CWE-327"),
				)
			},
			expected: []string{"security", "static-analysis", "code-quality", "CWE-327"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.findingFn()
			tags := writer.buildTags(f)
			for _, expected := range tt.expected {
				assert.Contains(t, tags, expected)
			}
		})
	}
}

func TestSARIFWriter_NormalizeFilePath(t *testing.T) {
	writer := NewSARIFWriter()

	tests := []struct {
		input    string
		expected string
	}{
		{"./pkg/handler.go", "pkg/handler.go"},
		{"pkg/handler.go", "pkg/handler.go"},
		{"pkg\\handler.go", "pkg/handler.go"}, // Windows-style path
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := writer.normalizeFilePath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSARIFWriter_NormalizeFilePath_AbsolutePaths(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		input    string
		expected string
	}{
		{
			name:     "absolute path with matching base",
			basePath: "/Users/dev/project",
			input:    "/Users/dev/project/pkg/handler.go",
			expected: "pkg/handler.go",
		},
		{
			name:     "absolute path with base ending in slash",
			basePath: "/Users/dev/project/",
			input:    "/Users/dev/project/internal/service.go",
			expected: "internal/service.go",
		},
		{
			name:     "absolute path not matching base",
			basePath: "/Users/dev/project",
			input:    "/Users/other/file.go",
			expected: "/Users/other/file.go",
		},
		{
			name:     "relative path unchanged",
			basePath: "/Users/dev/project",
			input:    "pkg/handler.go",
			expected: "pkg/handler.go",
		},
		{
			name:     "Windows-style absolute path",
			basePath: "C:\\Users\\dev\\project",
			input:    "C:\\Users\\dev\\project\\pkg\\handler.go",
			expected: "pkg/handler.go",
		},
		{
			name:     "empty base path keeps absolute path",
			basePath: "",
			input:    "/Users/dev/project/file.go",
			expected: "/Users/dev/project/file.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := NewSARIFWriter(WithBasePath(tt.basePath))
			result := writer.normalizeFilePath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSARIFWriter_WithBasePath(t *testing.T) {
	basePath := "/custom/base/path"
	writer := NewSARIFWriter(WithBasePath(basePath))
	assert.Equal(t, basePath, writer.basePath)
}

func TestSARIFWriter_DefaultBasePath(t *testing.T) {
	writer := NewSARIFWriter()
	// Should have the current working directory as default
	assert.NotEmpty(t, writer.basePath)
}

func TestSARIFWriter_WriteSummary(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))

	a := assessment.NewAssessment("test-target")
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	// WriteSummary should produce same output as WriteAssessment for SARIF
	err := writer.WriteSummary(a, result)
	require.NoError(t, err)

	var sarif SARIFLog
	err = json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)
	assert.Equal(t, SARIFVersion, sarif.Version)
}

func TestSARIFWriter_WriteProgress(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))

	// WriteProgress is no-op for SARIF
	err := writer.WriteProgress("Scanning...")
	assert.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestSARIFWriter_WriteError(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))

	// WriteError is no-op for SARIF
	err := writer.WriteError(assert.AnError)
	assert.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestSARIFWriter_Flush(t *testing.T) {
	writer := NewSARIFWriter()
	err := writer.Flush()
	assert.NoError(t, err)
}

func TestSARIFWriter_Close(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))
	err := writer.Close()
	assert.NoError(t, err)
}

func TestSARIFWriter_WithCVE(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))

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

	var sarif SARIFLog
	err = json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)

	res := sarif.Runs[0].Results[0]
	assert.Len(t, res.RelatedLocations, 1)
	assert.Contains(t, res.RelatedLocations[0].Message.Text, "CVE-2023-1234")
}

func TestSARIFWriter_Invocations(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSARIFWriter(WithSARIFOutput(&buf))

	a := assessment.NewAssessment("test-target")
	time.Sleep(10 * time.Millisecond) // Ensure some time passes
	a.Complete()

	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
	}

	err := writer.WriteAssessment(a, result)
	require.NoError(t, err)

	var sarif SARIFLog
	err = json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)

	assert.Len(t, sarif.Runs[0].Invocations, 1)
	inv := sarif.Runs[0].Invocations[0]
	assert.True(t, inv.ExecutionSuccessful)
	assert.NotEmpty(t, inv.StartTimeUTC)
	assert.NotEmpty(t, inv.EndTimeUTC)
}

func TestSARIFWriter_ImplementsInterface(t *testing.T) {
	writer := NewSARIFWriter()
	var _ ports.SARIFWriter = writer
}
