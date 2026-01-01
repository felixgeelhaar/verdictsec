package services

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func createDiffFinding(ruleID string, severity finding.Severity, line int) *finding.Finding {
	loc := finding.NewLocation("main.go", line, 1, line, 20)
	return finding.NewFinding(finding.FindingTypeSAST, "gosec", ruleID, "Test", severity, loc)
}

const testDiffReason = "Test baseline reason"

func TestNewDiffService(t *testing.T) {
	svc := NewDiffService()
	assert.NotNil(t, svc)
}

func TestDiffService_Diff_NilBaseline(t *testing.T) {
	svc := NewDiffService()
	findings := []*finding.Finding{
		createDiffFinding("G401", finding.SeverityHigh, 10),
		createDiffFinding("G402", finding.SeverityMedium, 20),
	}

	result := svc.Diff(findings, nil)

	assert.Len(t, result.New, 2)
	assert.Empty(t, result.Existing)
	assert.Empty(t, result.Resolved)
}

func TestDiffService_Diff_AllNew(t *testing.T) {
	svc := NewDiffService()
	base := baseline.NewBaseline("./src")

	findings := []*finding.Finding{
		createDiffFinding("G401", finding.SeverityHigh, 10),
		createDiffFinding("G402", finding.SeverityMedium, 20),
	}

	result := svc.Diff(findings, base)

	assert.Len(t, result.New, 2)
	assert.Empty(t, result.Existing)
	assert.Empty(t, result.Resolved)
}

func TestDiffService_Diff_AllExisting(t *testing.T) {
	svc := NewDiffService()
	base := baseline.NewBaseline("./src")

	f1 := createDiffFinding("G401", finding.SeverityHigh, 10)
	f2 := createDiffFinding("G402", finding.SeverityMedium, 20)

	_ = base.Add(f1, testDiffReason)
	_ = base.Add(f2, testDiffReason)

	result := svc.Diff([]*finding.Finding{f1, f2}, base)

	assert.Empty(t, result.New)
	assert.Len(t, result.Existing, 2)
	assert.Empty(t, result.Resolved)
}

func TestDiffService_Diff_Mixed(t *testing.T) {
	svc := NewDiffService()
	base := baseline.NewBaseline("./src")

	existingFinding := createDiffFinding("G401", finding.SeverityHigh, 10)
	newFinding := createDiffFinding("G402", finding.SeverityMedium, 20)

	_ = base.Add(existingFinding, testDiffReason)

	result := svc.Diff([]*finding.Finding{existingFinding, newFinding}, base)

	assert.Len(t, result.New, 1)
	assert.Len(t, result.Existing, 1)
	assert.Empty(t, result.Resolved)
}

func TestDiffService_Diff_Resolved(t *testing.T) {
	svc := NewDiffService()
	base := baseline.NewBaseline("./src")

	resolvedFinding := createDiffFinding("G401", finding.SeverityHigh, 10)
	_ = base.Add(resolvedFinding, testDiffReason)

	result := svc.Diff([]*finding.Finding{}, base)

	assert.Empty(t, result.New)
	assert.Empty(t, result.Existing)
	assert.Len(t, result.Resolved, 1)
	assert.Equal(t, resolvedFinding.Fingerprint().Value(), result.Resolved[0])
}

func TestDiffService_Diff_ComplexScenario(t *testing.T) {
	svc := NewDiffService()
	base := baseline.NewBaseline("./src")

	// Baseline has f1, f2, f3
	f1 := createDiffFinding("G401", finding.SeverityHigh, 10)
	f2 := createDiffFinding("G402", finding.SeverityMedium, 20)
	f3 := createDiffFinding("G403", finding.SeverityLow, 30)
	_ = base.Add(f1, testDiffReason)
	_ = base.Add(f2, testDiffReason)
	_ = base.Add(f3, testDiffReason)

	// Current has f1, f4
	f4 := createDiffFinding("G404", finding.SeverityHigh, 40)

	result := svc.Diff([]*finding.Finding{f1, f4}, base)

	assert.Len(t, result.New, 1)
	assert.Equal(t, f4.Fingerprint().Value(), result.New[0].Fingerprint().Value())

	assert.Len(t, result.Existing, 1)
	assert.Equal(t, f1.Fingerprint().Value(), result.Existing[0].Fingerprint().Value())

	assert.Len(t, result.Resolved, 2)
}

func TestDiffResult_Stats(t *testing.T) {
	result := DiffResult{
		New:      make([]*finding.Finding, 3),
		Existing: make([]*finding.Finding, 2),
		Resolved: []string{"a", "b"},
	}

	stats := result.Stats()

	assert.Equal(t, 3, stats.NewCount)
	assert.Equal(t, 2, stats.ExistingCount)
	assert.Equal(t, 2, stats.ResolvedCount)
}

func TestDiffResult_HasNew(t *testing.T) {
	resultWithNew := DiffResult{New: []*finding.Finding{{}}}
	resultWithoutNew := DiffResult{New: []*finding.Finding{}}

	assert.True(t, resultWithNew.HasNew())
	assert.False(t, resultWithoutNew.HasNew())
}

func TestDiffResult_HasResolved(t *testing.T) {
	resultWithResolved := DiffResult{Resolved: []string{"a"}}
	resultWithoutResolved := DiffResult{Resolved: []string{}}

	assert.True(t, resultWithResolved.HasResolved())
	assert.False(t, resultWithoutResolved.HasResolved())
}

func TestDiffResult_TotalCurrent(t *testing.T) {
	result := DiffResult{
		New:      make([]*finding.Finding, 3),
		Existing: make([]*finding.Finding, 2),
	}

	assert.Equal(t, 5, result.TotalCurrent())
}

func TestDiffResult_NewBySeverity(t *testing.T) {
	f1 := createDiffFinding("G401", finding.SeverityHigh, 10)
	f2 := createDiffFinding("G402", finding.SeverityMedium, 20)
	f3 := createDiffFinding("G403", finding.SeverityLow, 30)

	result := DiffResult{
		New: []*finding.Finding{f1, f2, f3},
	}

	high := result.NewBySeverity(finding.SeverityHigh)
	assert.Len(t, high, 1)

	medium := result.NewBySeverity(finding.SeverityMedium)
	assert.Len(t, medium, 2)

	low := result.NewBySeverity(finding.SeverityLow)
	assert.Len(t, low, 3)
}

func TestDiffResult_NewByType(t *testing.T) {
	loc := finding.NewLocation("main.go", 10, 1, 10, 20)
	sastFinding := finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "Test", finding.SeverityHigh, loc)
	vulnFinding := finding.NewFinding(finding.FindingTypeVuln, "govulncheck", "CVE-2024-1234", "Test", finding.SeverityHigh, loc)

	result := DiffResult{
		New: []*finding.Finding{sastFinding, vulnFinding},
	}

	sast := result.NewByType(finding.FindingTypeSAST)
	assert.Len(t, sast, 1)

	vuln := result.NewByType(finding.FindingTypeVuln)
	assert.Len(t, vuln, 1)

	secret := result.NewByType(finding.FindingTypeSecret)
	assert.Empty(t, secret)
}
