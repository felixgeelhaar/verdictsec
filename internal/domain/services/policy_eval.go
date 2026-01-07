package services

import (
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
)

// EvaluationResult contains the results of policy evaluation.
type EvaluationResult struct {
	Decision        assessment.Decision
	Reasons         []string
	NewFindings     []*finding.Finding
	Existing        []*finding.Finding
	Suppressed      []*finding.Finding
	InlineSuppressed []*finding.Finding // Findings suppressed by inline comments
	Score           Score              // Security score (0-100 with A-F grade)
}

// PolicyEvaluationService evaluates findings against policy.
// It is a domain service that produces deterministic decisions.
type PolicyEvaluationService struct{}

// NewPolicyEvaluationService creates a new policy evaluation service.
func NewPolicyEvaluationService() *PolicyEvaluationService {
	return &PolicyEvaluationService{}
}

// Evaluate applies policy to findings and determines decision.
// The evaluation is deterministic: same inputs always produce same outputs.
func (s *PolicyEvaluationService) Evaluate(
	findings []*finding.Finding,
	pol *policy.Policy,
	base *baseline.Baseline,
	mode policy.Mode,
) EvaluationResult {
	result := EvaluationResult{
		Decision:    assessment.DecisionPass,
		Reasons:     []string{},
		NewFindings: []*finding.Finding{},
		Existing:    []*finding.Finding{},
		Suppressed:  []*finding.Finding{},
	}

	if len(findings) == 0 {
		result.Reasons = append(result.Reasons, "No findings detected")
		return result
	}

	threshold := pol.GetThresholdForMode(mode)

	for _, f := range findings {
		// Check suppression first
		if pol.IsSuppressed(f) {
			result.Suppressed = append(result.Suppressed, f)
			continue
		}

		// Check baseline
		isBaselined := base != nil && base.Contains(f)
		if isBaselined {
			result.Existing = append(result.Existing, f)

			// In strict mode, baselined findings don't affect decision
			if pol.BaselineMode == policy.BaselineModeStrict {
				continue
			}
		} else {
			result.NewFindings = append(result.NewFindings, f)
		}

		// Apply thresholds
		severity := f.EffectiveSeverity()

		if threshold.ShouldFail(severity) {
			result.Decision = assessment.DecisionFail
			prefix := "New"
			if isBaselined {
				prefix = "Existing"
			}
			result.Reasons = append(result.Reasons,
				fmt.Sprintf("%s finding %s has severity %s >= fail threshold %s",
					prefix,
					f.Fingerprint().Short(),
					severity,
					threshold.FailOn))
		} else if threshold.ShouldWarn(severity) {
			if result.Decision < assessment.DecisionWarn {
				result.Decision = assessment.DecisionWarn
			}
			prefix := "New"
			if isBaselined {
				prefix = "Existing"
			}
			result.Reasons = append(result.Reasons,
				fmt.Sprintf("%s finding %s has severity %s >= warn threshold %s",
					prefix,
					f.Fingerprint().Short(),
					severity,
					threshold.WarnOn))
		}
	}

	// Add summary to reasons
	if result.Decision == assessment.DecisionPass && len(findings) > 0 {
		result.Reasons = append(result.Reasons,
			fmt.Sprintf("All %d findings below threshold", len(findings)))
	}

	return result
}

// EvaluateWithStats provides additional statistics about the evaluation.
func (s *PolicyEvaluationService) EvaluateWithStats(
	findings []*finding.Finding,
	pol *policy.Policy,
	base *baseline.Baseline,
	mode policy.Mode,
) (EvaluationResult, EvaluationStats) {
	result := s.Evaluate(findings, pol, base, mode)

	stats := EvaluationStats{
		TotalFindings:        len(findings),
		NewFindings:          len(result.NewFindings),
		ExistingFindings:     len(result.Existing),
		SuppressedFindings:   len(result.Suppressed),
		InlineSuppressedFindings: len(result.InlineSuppressed),
		SeverityCounts:       make(map[finding.Severity]int),
	}

	// Count by severity (excluding suppressed)
	for _, f := range result.NewFindings {
		stats.SeverityCounts[f.EffectiveSeverity()]++
	}
	for _, f := range result.Existing {
		stats.SeverityCounts[f.EffectiveSeverity()]++
	}

	return result, stats
}

// EvaluationStats provides statistics about the evaluation.
type EvaluationStats struct {
	TotalFindings            int
	NewFindings              int
	ExistingFindings         int
	SuppressedFindings       int
	InlineSuppressedFindings int
	SeverityCounts           map[finding.Severity]int
}

// CriticalCount returns the number of critical findings.
func (s EvaluationStats) CriticalCount() int {
	return s.SeverityCounts[finding.SeverityCritical]
}

// HighCount returns the number of high severity findings.
func (s EvaluationStats) HighCount() int {
	return s.SeverityCounts[finding.SeverityHigh]
}

// MediumCount returns the number of medium severity findings.
func (s EvaluationStats) MediumCount() int {
	return s.SeverityCounts[finding.SeverityMedium]
}

// LowCount returns the number of low severity findings.
func (s EvaluationStats) LowCount() int {
	return s.SeverityCounts[finding.SeverityLow]
}

// InlineSuppressedCount returns the number of inline suppressed findings.
func (s EvaluationStats) InlineSuppressedCount() int {
	return s.InlineSuppressedFindings
}
