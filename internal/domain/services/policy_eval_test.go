package services

import (
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
	"github.com/stretchr/testify/assert"
)

func createFinding(ruleID string, severity finding.Severity) *finding.Finding {
	loc := finding.NewLocation("main.go", 10, 1, 10, 20)
	return finding.NewFinding(finding.FindingTypeSAST, "gosec", ruleID, "Test", severity, loc)
}

func TestNewPolicyEvaluationService(t *testing.T) {
	svc := NewPolicyEvaluationService()
	assert.NotNil(t, svc)
}

func defaultPolicy() *policy.Policy {
	pol := policy.DefaultPolicy()
	return &pol
}

func TestPolicyEvaluationService_Evaluate_NoFindings(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()

	result := svc.Evaluate([]*finding.Finding{}, pol, nil, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionPass, result.Decision)
	assert.Contains(t, result.Reasons, "No findings detected")
	assert.Empty(t, result.NewFindings)
	assert.Empty(t, result.Existing)
	assert.Empty(t, result.Suppressed)
}

func TestPolicyEvaluationService_Evaluate_HighSeverityFails(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()
	findings := []*finding.Finding{
		createFinding("G401", finding.SeverityHigh),
	}

	result := svc.Evaluate(findings, pol, nil, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionFail, result.Decision)
	assert.Len(t, result.NewFindings, 1)
	assert.Empty(t, result.Existing)
}

func TestPolicyEvaluationService_Evaluate_MediumSeverityWarns(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()
	findings := []*finding.Finding{
		createFinding("G401", finding.SeverityMedium),
	}

	result := svc.Evaluate(findings, pol, nil, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionWarn, result.Decision)
	assert.Len(t, result.NewFindings, 1)
}

func TestPolicyEvaluationService_Evaluate_LowSeverityPasses(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()
	findings := []*finding.Finding{
		createFinding("G401", finding.SeverityLow),
	}

	result := svc.Evaluate(findings, pol, nil, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionPass, result.Decision)
	assert.Len(t, result.NewFindings, 1)
	assert.Contains(t, result.Reasons[0], "below threshold")
}

func TestPolicyEvaluationService_Evaluate_SuppressedFinding(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()

	f := createFinding("G401", finding.SeverityHigh)
	findings := []*finding.Finding{f}

	// Add suppression for this finding
	pol.Suppressions = append(pol.Suppressions, policy.Suppression{
		Fingerprint: f.Fingerprint().Value(),
		Reason:      "False positive",
		Owner:       "test@example.com",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	})

	result := svc.Evaluate(findings, pol, nil, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionPass, result.Decision)
	assert.Empty(t, result.NewFindings)
	assert.Len(t, result.Suppressed, 1)
}

func TestPolicyEvaluationService_Evaluate_BaselinedFinding(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()

	f := createFinding("G401", finding.SeverityHigh)
	findings := []*finding.Finding{f}

	// Add to baseline
	base := baseline.NewBaseline("./src")
	_ = base.Add(f, "Test baseline reason")

	result := svc.Evaluate(findings, pol, base, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionFail, result.Decision)
	assert.Empty(t, result.NewFindings)
	assert.Len(t, result.Existing, 1)
}

func TestPolicyEvaluationService_Evaluate_StrictBaselineMode(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()
	pol.BaselineMode = policy.BaselineModeStrict

	f := createFinding("G401", finding.SeverityHigh)
	findings := []*finding.Finding{f}

	// Add to baseline
	base := baseline.NewBaseline("./src")
	_ = base.Add(f, "Test baseline reason")

	result := svc.Evaluate(findings, pol, base, policy.ModeLocal)

	// In strict mode, baselined findings don't affect decision
	assert.Equal(t, assessment.DecisionPass, result.Decision)
	assert.Empty(t, result.NewFindings)
	assert.Len(t, result.Existing, 1)
}

func TestPolicyEvaluationService_Evaluate_MixedFindings(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()

	f1 := createFinding("G401", finding.SeverityHigh)     // Should fail
	f2 := createFinding("G402", finding.SeverityMedium)   // Should warn
	f3 := createFinding("G403", finding.SeverityLow)      // Below threshold
	f4 := createFinding("G404", finding.SeverityCritical) // Should fail

	findings := []*finding.Finding{f1, f2, f3, f4}

	result := svc.Evaluate(findings, pol, nil, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionFail, result.Decision)
	assert.Len(t, result.NewFindings, 4)
	assert.True(t, len(result.Reasons) > 0)
}

func TestPolicyEvaluationService_EvaluateWithStats(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()

	f1 := createFinding("G401", finding.SeverityHigh)
	f2 := createFinding("G402", finding.SeverityMedium)
	f3 := createFinding("G403", finding.SeverityLow)

	findings := []*finding.Finding{f1, f2, f3}

	result, stats := svc.EvaluateWithStats(findings, pol, nil, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionFail, result.Decision)
	assert.Equal(t, 3, stats.TotalFindings)
	assert.Equal(t, 3, stats.NewFindings)
	assert.Equal(t, 0, stats.ExistingFindings)
	assert.Equal(t, 0, stats.SuppressedFindings)
	assert.Equal(t, 1, stats.HighCount())
	assert.Equal(t, 1, stats.MediumCount())
	assert.Equal(t, 1, stats.LowCount())
}

func TestPolicyEvaluationService_EvaluateWithStats_CriticalCount(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()

	f := createFinding("G401", finding.SeverityCritical)
	findings := []*finding.Finding{f}

	_, stats := svc.EvaluateWithStats(findings, pol, nil, policy.ModeLocal)

	assert.Equal(t, 1, stats.CriticalCount())
}

func TestPolicyEvaluationService_Evaluate_CIModeThreshold(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()

	// Add stricter CI mode threshold
	pol.GatingRules = append(pol.GatingRules, policy.GatingRule{
		Mode: policy.ModeCI,
		Threshold: policy.Threshold{
			FailOn: finding.SeverityMedium,
			WarnOn: finding.SeverityLow,
		},
	})

	f := createFinding("G401", finding.SeverityMedium)
	findings := []*finding.Finding{f}

	// Local mode - should only warn
	resultLocal := svc.Evaluate(findings, pol, nil, policy.ModeLocal)
	assert.Equal(t, assessment.DecisionWarn, resultLocal.Decision)

	// CI mode - should fail
	resultCI := svc.Evaluate(findings, pol, nil, policy.ModeCI)
	assert.Equal(t, assessment.DecisionFail, resultCI.Decision)
}

func TestPolicyEvaluationService_Evaluate_ExistingFindingReasons(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()

	f := createFinding("G401", finding.SeverityHigh)
	findings := []*finding.Finding{f}

	// Add to baseline
	base := baseline.NewBaseline("./src")
	_ = base.Add(f, "Test baseline reason")

	result := svc.Evaluate(findings, pol, base, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionFail, result.Decision)
	// Reason should mention "Existing"
	assert.Contains(t, result.Reasons[0], "Existing")
}

func TestPolicyEvaluationService_Evaluate_WarningReasons(t *testing.T) {
	svc := NewPolicyEvaluationService()
	pol := defaultPolicy()

	f := createFinding("G401", finding.SeverityMedium)
	findings := []*finding.Finding{f}

	result := svc.Evaluate(findings, pol, nil, policy.ModeLocal)

	assert.Equal(t, assessment.DecisionWarn, result.Decision)
	assert.Contains(t, result.Reasons[0], "warn threshold")
}
