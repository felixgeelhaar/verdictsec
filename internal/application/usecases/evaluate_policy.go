package usecases

import (
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// EvaluatePolicyInput contains the input for policy evaluation.
type EvaluatePolicyInput struct {
	Assessment *assessment.Assessment
	Policy     *policy.Policy
	Baseline   *baseline.Baseline
	Mode       policy.Mode
}

// EvaluatePolicyOutput contains the result of policy evaluation.
type EvaluatePolicyOutput struct {
	Decision assessment.Decision
	Result   services.EvaluationResult
	Stats    services.EvaluationStats
}

// EvaluatePolicyUseCase evaluates scan results against policy.
type EvaluatePolicyUseCase struct {
	policyService *services.PolicyEvaluationService
	diffService   *services.DiffService
	writer        ports.ArtifactWriter
}

// NewEvaluatePolicyUseCase creates a new policy evaluation use case.
func NewEvaluatePolicyUseCase(writer ports.ArtifactWriter) *EvaluatePolicyUseCase {
	return &EvaluatePolicyUseCase{
		policyService: services.NewPolicyEvaluationService(),
		diffService:   services.NewDiffService(),
		writer:        writer,
	}
}

// Execute evaluates the assessment against policy.
func (uc *EvaluatePolicyUseCase) Execute(input EvaluatePolicyInput) EvaluatePolicyOutput {
	// Get findings from assessment
	findings := input.Assessment.Findings()

	// Evaluate against policy
	result, stats := uc.policyService.EvaluateWithStats(
		findings,
		input.Policy,
		input.Baseline,
		input.Mode,
	)

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
func (uc *EvaluatePolicyUseCase) EvaluateWithDiff(input EvaluatePolicyInput) (EvaluatePolicyOutput, services.DiffResult) {
	output := uc.Execute(input)

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
func (uc *EvaluatePolicyUseCase) QuickEvaluate(input QuickEvaluateInput) EvaluatePolicyOutput {
	pol := input.Config.Policy
	return uc.Execute(EvaluatePolicyInput{
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
