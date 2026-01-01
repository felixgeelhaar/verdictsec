package usecases

import (
	"context"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
	"github.com/stretchr/testify/assert"
)

func createTestFinding(ruleID string, severity finding.Severity) *finding.Finding {
	loc := finding.NewLocation("main.go", 10, 1, 10, 20)
	return finding.NewFinding(finding.FindingTypeSAST, "gosec", ruleID, "Test", severity, loc)
}

func TestNewEvaluatePolicyUseCase(t *testing.T) {
	uc := NewEvaluatePolicyUseCase(nil)
	assert.NotNil(t, uc)
}

func TestEvaluatePolicyUseCase_Execute_NoFindings(t *testing.T) {
	uc := NewEvaluatePolicyUseCase(nil)
	a := assessment.NewAssessment("/test")
	pol := policy.DefaultPolicy()

	output := uc.Execute(context.Background(), EvaluatePolicyInput{
		Assessment: a,
		Policy:     &pol,
		Baseline:   nil,
		Mode:       policy.ModeLocal,
	})

	assert.Equal(t, assessment.DecisionPass, output.Decision)
	assert.Equal(t, 0, output.Stats.TotalFindings)
}

func TestEvaluatePolicyUseCase_Execute_HighSeverityFails(t *testing.T) {
	uc := NewEvaluatePolicyUseCase(nil)
	a := assessment.NewAssessment("/test")
	a.AddFinding(createTestFinding("G401", finding.SeverityHigh))
	pol := policy.DefaultPolicy()

	output := uc.Execute(context.Background(), EvaluatePolicyInput{
		Assessment: a,
		Policy:     &pol,
		Baseline:   nil,
		Mode:       policy.ModeLocal,
	})

	assert.Equal(t, assessment.DecisionFail, output.Decision)
	assert.Equal(t, 1, output.Stats.TotalFindings)
	assert.Equal(t, 1, output.Stats.NewFindings)
}

func TestEvaluatePolicyUseCase_Execute_MediumSeverityWarns(t *testing.T) {
	uc := NewEvaluatePolicyUseCase(nil)
	a := assessment.NewAssessment("/test")
	a.AddFinding(createTestFinding("G401", finding.SeverityMedium))
	pol := policy.DefaultPolicy()

	output := uc.Execute(context.Background(), EvaluatePolicyInput{
		Assessment: a,
		Policy:     &pol,
		Baseline:   nil,
		Mode:       policy.ModeLocal,
	})

	assert.Equal(t, assessment.DecisionWarn, output.Decision)
}

func TestEvaluatePolicyUseCase_Execute_WithBaseline(t *testing.T) {
	uc := NewEvaluatePolicyUseCase(nil)

	f := createTestFinding("G401", finding.SeverityHigh)
	a := assessment.NewAssessment("/test")
	a.AddFinding(f)

	pol := policy.DefaultPolicy()

	// Add finding to baseline
	base := baseline.NewBaseline("/test")
	_ = base.Add(f, "Test baseline reason")

	output := uc.Execute(context.Background(), EvaluatePolicyInput{
		Assessment: a,
		Policy:     &pol,
		Baseline:   base,
		Mode:       policy.ModeLocal,
	})

	assert.Equal(t, assessment.DecisionFail, output.Decision) // Still fails in warn mode
	assert.Equal(t, 0, output.Stats.NewFindings)
	assert.Equal(t, 1, output.Stats.ExistingFindings)
}

func TestEvaluatePolicyUseCase_EvaluateWithDiff(t *testing.T) {
	uc := NewEvaluatePolicyUseCase(nil)

	existingFinding := createTestFinding("G401", finding.SeverityHigh)
	newFinding := createTestFinding("G402", finding.SeverityMedium)

	a := assessment.NewAssessment("/test")
	a.AddFinding(existingFinding)
	a.AddFinding(newFinding)

	pol := policy.DefaultPolicy()

	base := baseline.NewBaseline("/test")
	_ = base.Add(existingFinding, "Test baseline reason")

	output, diff := uc.EvaluateWithDiff(context.Background(), EvaluatePolicyInput{
		Assessment: a,
		Policy:     &pol,
		Baseline:   base,
		Mode:       policy.ModeLocal,
	})

	assert.Equal(t, assessment.DecisionFail, output.Decision)
	assert.Len(t, diff.New, 1)
	assert.Len(t, diff.Existing, 1)
}

func TestEvaluatePolicyUseCase_QuickEvaluate(t *testing.T) {
	uc := NewEvaluatePolicyUseCase(nil)
	a := assessment.NewAssessment("/test")
	a.AddFinding(createTestFinding("G401", finding.SeverityLow))

	cfg := ports.DefaultConfig()

	output := uc.QuickEvaluate(context.Background(), QuickEvaluateInput{
		Assessment: a,
		Config:     cfg,
		Mode:       policy.ModeLocal,
	})

	assert.Equal(t, assessment.DecisionPass, output.Decision)
}

func TestEvaluatePolicyOutput_ShouldFail(t *testing.T) {
	passOutput := EvaluatePolicyOutput{Decision: assessment.DecisionPass}
	warnOutput := EvaluatePolicyOutput{Decision: assessment.DecisionWarn}
	failOutput := EvaluatePolicyOutput{Decision: assessment.DecisionFail}
	errorOutput := EvaluatePolicyOutput{Decision: assessment.DecisionError}

	assert.False(t, passOutput.ShouldFail())
	assert.False(t, warnOutput.ShouldFail())
	assert.True(t, failOutput.ShouldFail())
	assert.True(t, errorOutput.ShouldFail())
}

func TestEvaluatePolicyOutput_ExitCode(t *testing.T) {
	passOutput := EvaluatePolicyOutput{Decision: assessment.DecisionPass}
	failOutput := EvaluatePolicyOutput{Decision: assessment.DecisionFail}
	errorOutput := EvaluatePolicyOutput{Decision: assessment.DecisionError}

	assert.Equal(t, 0, passOutput.ExitCode())
	assert.Equal(t, 1, failOutput.ExitCode())
	assert.Equal(t, 2, errorOutput.ExitCode())
}
