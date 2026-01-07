package usecases

import (
	"context"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/suppression"
)

// EvaluatePolicyInput contains the input for policy evaluation.
type EvaluatePolicyInput struct {
	Assessment               *assessment.Assessment
	Policy                   *policy.Policy
	Baseline                 *baseline.Baseline
	Mode                     policy.Mode
	InlineSuppressionsEnabled bool
	TargetDir                string // Target directory for inline suppression parsing
}

// EvaluatePolicyOutput contains the result of policy evaluation.
type EvaluatePolicyOutput struct {
	Decision assessment.Decision
	Result   services.EvaluationResult
	Stats    services.EvaluationStats
}

// EvaluatePolicyUseCase evaluates scan results against policy.
type EvaluatePolicyUseCase struct {
	policyService      *services.PolicyEvaluationService
	diffService        *services.DiffService
	scoreService       *services.ScoreService
	suppressionService *suppression.InlineSuppressionService
	writer             ports.ArtifactWriter
}

// NewEvaluatePolicyUseCase creates a new policy evaluation use case.
func NewEvaluatePolicyUseCase(writer ports.ArtifactWriter) *EvaluatePolicyUseCase {
	return &EvaluatePolicyUseCase{
		policyService:      services.NewPolicyEvaluationService(),
		diffService:        services.NewDiffService(),
		scoreService:       services.NewScoreService(),
		suppressionService: suppression.NewInlineSuppressionService(),
		writer:             writer,
	}
}

// Execute evaluates the assessment against policy.
func (uc *EvaluatePolicyUseCase) Execute(_ context.Context, input EvaluatePolicyInput) EvaluatePolicyOutput {
	// Get findings from assessment
	findings := input.Assessment.Findings()

	// Apply inline suppressions if enabled
	var inlineSuppressed []*finding.Finding
	if input.InlineSuppressionsEnabled && input.TargetDir != "" {
		matcher, err := uc.suppressionService.ParseAndMatch(input.TargetDir, findings)
		if err == nil && matcher != nil {
			inlineSuppressed, findings = matcher.PartitionFindings(findings)
		}
		// If parsing fails, we just continue with all findings
	}

	// Evaluate against policy (with inline suppressed findings removed)
	result, stats := uc.policyService.EvaluateWithStats(
		findings,
		input.Policy,
		input.Baseline,
		input.Mode,
	)

	// Add inline suppressed findings to result
	result.InlineSuppressed = inlineSuppressed
	stats.InlineSuppressedFindings = len(inlineSuppressed)

	// Calculate diff for score bonuses
	var diffResult *services.DiffResult
	if input.Baseline != nil {
		diff := uc.diffService.Diff(findings, input.Baseline)
		diffResult = &diff
	}

	// Calculate security score (based on non-inline-suppressed findings)
	result.Score = uc.scoreService.Calculate(findings, input.Baseline, diffResult)

	// Set decision on assessment
	input.Assessment.SetDecision(result.Decision, result.Reasons)

	// Write output
	if uc.writer != nil {
		_ = uc.writer.WriteAssessment(input.Assessment, result)
	}

	return EvaluatePolicyOutput{
		Decision: result.Decision,
		Result:   result,
		Stats:    stats,
	}
}

// EvaluateWithDiff evaluates and also computes diff against baseline.
func (uc *EvaluatePolicyUseCase) EvaluateWithDiff(ctx context.Context, input EvaluatePolicyInput) (EvaluatePolicyOutput, services.DiffResult) {
	output := uc.Execute(ctx, input)

	// Compute diff
	diff := uc.diffService.Diff(input.Assessment.Findings(), input.Baseline)

	return output, diff
}

// QuickEvaluateInput is a simplified input for quick evaluation.
type QuickEvaluateInput struct {
	Assessment *assessment.Assessment
	Config     ports.Config
	Mode       policy.Mode
}

// QuickEvaluate evaluates using config's embedded policy.
func (uc *EvaluatePolicyUseCase) QuickEvaluate(ctx context.Context, input QuickEvaluateInput) EvaluatePolicyOutput {
	pol := input.Config.Policy
	return uc.Execute(ctx, EvaluatePolicyInput{
		Assessment: input.Assessment,
		Policy:     &pol,
		Baseline:   nil,
		Mode:       input.Mode,
	})
}

// ShouldFail returns true if the decision should cause a non-zero exit.
func (o EvaluatePolicyOutput) ShouldFail() bool {
	return o.Decision == assessment.DecisionFail || o.Decision == assessment.DecisionError
}

// ExitCode returns the appropriate exit code for this result.
func (o EvaluatePolicyOutput) ExitCode() int {
	return o.Decision.ExitCode()
}
