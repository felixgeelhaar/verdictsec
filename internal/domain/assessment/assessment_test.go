package assessment

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAssessment(t *testing.T) {
	a := NewAssessment("/path/to/project")

	assert.NotEmpty(t, a.ID())
	assert.True(t, strings.HasPrefix(a.ID(), "assessment-"))
	assert.Equal(t, "/path/to/project", a.Target())
	assert.False(t, a.StartedAt().IsZero())
	assert.True(t, a.CompletedAt().IsZero())
	assert.False(t, a.IsCompleted())
	assert.Equal(t, DecisionUnknown, a.Decision())
	assert.Empty(t, a.Reasons())
	assert.Empty(t, a.Findings())
	assert.Empty(t, a.EngineRuns())
}

func TestAssessment_AddFinding(t *testing.T) {
	a := NewAssessment("/test")
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)

	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G401",
		"Test finding",
		finding.SeverityHigh,
		loc,
	)

	a.AddFinding(f)
	assert.Len(t, a.Findings(), 1)
	assert.Equal(t, 1, a.FindingCount())
}

func TestAssessment_AddFindings(t *testing.T) {
	a := NewAssessment("/test")
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)

	findings := []*finding.Finding{
		finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "Test 1", finding.SeverityHigh, loc),
		finding.NewFinding(finding.FindingTypeSAST, "gosec", "G402", "Test 2", finding.SeverityMedium, loc),
	}

	a.AddFindings(findings)
	assert.Len(t, a.Findings(), 2)
}

func TestAssessment_AddEngineRun(t *testing.T) {
	a := NewAssessment("/test")

	run := NewEngineRun("gosec", "2.18.0")
	run.Complete(5)

	a.AddEngineRun(run)
	assert.Len(t, a.EngineRuns(), 1)
	assert.Equal(t, 1, a.SuccessfulEngineRuns())
	assert.Equal(t, 0, a.FailedEngineRuns())
}

func TestAssessment_SetDecision(t *testing.T) {
	a := NewAssessment("/test")

	a.SetDecision(DecisionFail, []string{"Reason 1", "Reason 2"})

	assert.Equal(t, DecisionFail, a.Decision())
	assert.Len(t, a.Reasons(), 2)
}

func TestAssessment_Complete(t *testing.T) {
	a := NewAssessment("/test")
	assert.False(t, a.IsCompleted())

	a.Complete()

	assert.True(t, a.IsCompleted())
	assert.False(t, a.CompletedAt().IsZero())
}

func TestAssessment_Duration(t *testing.T) {
	a := NewAssessment("/test")

	// Not completed yet - duration should be >= 0 (can be 0 on fast systems)
	duration := a.Duration()
	assert.GreaterOrEqual(t, duration, time.Duration(0))

	time.Sleep(10 * time.Millisecond)
	a.Complete()

	duration = a.Duration()
	assert.Greater(t, duration, 10*time.Millisecond)
}

func TestAssessment_FindingsByType(t *testing.T) {
	a := NewAssessment("/test")
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)

	a.AddFinding(finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "SAST", finding.SeverityHigh, loc))
	a.AddFinding(finding.NewFinding(finding.FindingTypeVuln, "govulncheck", "GO-1", "Vuln", finding.SeverityHigh, loc))
	a.AddFinding(finding.NewFinding(finding.FindingTypeSAST, "gosec", "G402", "SAST 2", finding.SeverityMedium, loc))

	sastFindings := a.FindingsByType(finding.FindingTypeSAST)
	assert.Len(t, sastFindings, 2)

	vulnFindings := a.FindingsByType(finding.FindingTypeVuln)
	assert.Len(t, vulnFindings, 1)
}

func TestAssessment_FindingsBySeverity(t *testing.T) {
	a := NewAssessment("/test")
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)

	a.AddFinding(finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "High", finding.SeverityHigh, loc))
	a.AddFinding(finding.NewFinding(finding.FindingTypeSAST, "gosec", "G402", "Medium", finding.SeverityMedium, loc))
	a.AddFinding(finding.NewFinding(finding.FindingTypeSAST, "gosec", "G403", "Low", finding.SeverityLow, loc))

	highAndAbove := a.FindingsBySeverity(finding.SeverityHigh)
	assert.Len(t, highAndAbove, 1)

	mediumAndAbove := a.FindingsBySeverity(finding.SeverityMedium)
	assert.Len(t, mediumAndAbove, 2)
}

func TestAssessment_Summary(t *testing.T) {
	a := NewAssessment("/test")
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)

	a.AddFinding(finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "High", finding.SeverityHigh, loc))
	a.AddFinding(finding.NewFinding(finding.FindingTypeSAST, "gosec", "G402", "High 2", finding.SeverityHigh, loc))
	a.AddFinding(finding.NewFinding(finding.FindingTypeSAST, "gosec", "G403", "Medium", finding.SeverityMedium, loc))

	summary := a.Summary()
	assert.Equal(t, 2, summary[finding.SeverityHigh])
	assert.Equal(t, 1, summary[finding.SeverityMedium])
}

func TestAssessment_Metadata(t *testing.T) {
	a := NewAssessment("/test")

	a.SetPolicyVersion("1.0")
	a.SetToolVersion("0.1.0")

	metadata := a.Metadata()
	assert.Equal(t, "1.0", metadata.PolicyVersion)
	assert.Equal(t, "0.1.0", metadata.ToolVersion)
	assert.Equal(t, "v1", metadata.NormalizationVersion)
}

func TestAssessment_JSONRoundTrip(t *testing.T) {
	a := NewAssessment("/test/project")
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)

	a.AddFinding(finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "Test", finding.SeverityHigh, loc))

	run := NewEngineRun("gosec", "2.18.0")
	run.Complete(1)
	a.AddEngineRun(run)

	a.SetDecision(DecisionPass, []string{"All good"})
	a.Complete()

	data, err := json.Marshal(a)
	require.NoError(t, err)

	var decoded Assessment
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, a.ID(), decoded.ID())
	assert.Equal(t, a.Target(), decoded.Target())
	assert.Equal(t, a.Decision(), decoded.Decision())
	assert.Len(t, decoded.Findings(), 1)
	assert.Len(t, decoded.EngineRuns(), 1)
}
