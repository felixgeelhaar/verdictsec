package usecases

import (
	"context"
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/git"
)

// DiffRefsInput contains the input for diff between git refs.
type DiffRefsInput struct {
	RepoPath string
	RefRange string           // "from..to" format
	Config   ports.Config
	Engines  []ports.EngineID
	NewOnly  bool             // Only show new findings
}

// DiffRefsOutput contains the result of diff between refs.
type DiffRefsOutput struct {
	FromRef        string
	ToRef          string
	FromAssessment *assessment.Assessment
	ToAssessment   *assessment.Assessment
	NewFindings    []*finding.Finding
	FixedFindings  []*finding.Finding
	Unchanged      []*finding.Finding
	Summary        DiffSummary
}

// DiffSummary contains summary statistics for the diff.
type DiffSummary struct {
	TotalNew      int
	TotalFixed    int
	TotalUnchanged int
	NewBySeverity map[finding.Severity]int
	FixedBySeverity map[finding.Severity]int
}

// DiffRefsUseCase compares security findings between git refs.
type DiffRefsUseCase struct {
	scanUseCase *RunScanUseCase
	diffService *services.DiffService
	writer      ports.ArtifactWriter
}

// NewDiffRefsUseCase creates a new diff refs use case.
func NewDiffRefsUseCase(
	scanUseCase *RunScanUseCase,
	writer ports.ArtifactWriter,
) *DiffRefsUseCase {
	return &DiffRefsUseCase{
		scanUseCase: scanUseCase,
		diffService: services.NewDiffService(),
		writer:      writer,
	}
}

// Execute runs the diff between two git refs.
func (uc *DiffRefsUseCase) Execute(ctx context.Context, input DiffRefsInput) (DiffRefsOutput, error) {
	output := DiffRefsOutput{
		Summary: DiffSummary{
			NewBySeverity:   make(map[finding.Severity]int),
			FixedBySeverity: make(map[finding.Severity]int),
		},
	}

	// Parse ref range
	refRange, err := git.ParseRefRange(input.RefRange)
	if err != nil {
		return output, fmt.Errorf("invalid ref range: %w", err)
	}
	output.FromRef = refRange.From
	output.ToRef = refRange.To

	// Create checkout helper
	helper := git.NewCheckoutHelper(input.RepoPath)
	defer helper.Cleanup()

	// Validate refs exist
	if err := helper.ValidateRef(refRange.From); err != nil {
		return output, fmt.Errorf("invalid 'from' ref: %w", err)
	}
	if err := helper.ValidateRef(refRange.To); err != nil {
		return output, fmt.Errorf("invalid 'to' ref: %w", err)
	}

	// Report progress
	if uc.writer != nil {
		_ = uc.writer.WriteProgress(fmt.Sprintf("Comparing %s..%s", refRange.From, refRange.To))
	}

	// Checkout 'from' ref to temp directory
	if uc.writer != nil {
		_ = uc.writer.WriteProgress(fmt.Sprintf("Checking out %s...", refRange.From))
	}
	fromDir, err := helper.CheckoutToTemp(refRange.From)
	if err != nil {
		return output, fmt.Errorf("failed to checkout 'from' ref: %w", err)
	}

	// Scan 'from' ref
	if uc.writer != nil {
		_ = uc.writer.WriteProgress(fmt.Sprintf("Scanning %s...", refRange.From))
	}
	fromScanOutput, err := uc.scanUseCase.Execute(ctx, RunScanInput{
		Target:   ports.Target{Path: fromDir},
		Config:   input.Config,
		Engines:  input.Engines,
		Parallel: true,
	})
	if err != nil {
		return output, fmt.Errorf("failed to scan 'from' ref: %w", err)
	}
	output.FromAssessment = fromScanOutput.Assessment

	// Determine 'to' directory - use working tree if it's HEAD or current branch
	toDir := input.RepoPath
	if refRange.To != "HEAD" {
		currentBranch, _ := helper.GetCurrentBranch()
		if refRange.To != currentBranch {
			// Checkout 'to' ref to temp directory
			if uc.writer != nil {
				_ = uc.writer.WriteProgress(fmt.Sprintf("Checking out %s...", refRange.To))
			}
			toDir, err = helper.CheckoutToTemp(refRange.To)
			if err != nil {
				return output, fmt.Errorf("failed to checkout 'to' ref: %w", err)
			}
		}
	}

	// Scan 'to' ref
	if uc.writer != nil {
		_ = uc.writer.WriteProgress(fmt.Sprintf("Scanning %s...", refRange.To))
	}
	toScanOutput, err := uc.scanUseCase.Execute(ctx, RunScanInput{
		Target:   ports.Target{Path: toDir},
		Config:   input.Config,
		Engines:  input.Engines,
		Parallel: true,
	})
	if err != nil {
		return output, fmt.Errorf("failed to scan 'to' ref: %w", err)
	}
	output.ToAssessment = toScanOutput.Assessment

	// Compute diff using fingerprints
	uc.computeDiff(&output)

	return output, nil
}

// computeDiff categorizes findings as new, fixed, or unchanged.
func (uc *DiffRefsUseCase) computeDiff(output *DiffRefsOutput) {
	fromFindings := output.FromAssessment.Findings()
	toFindings := output.ToAssessment.Findings()

	// Build fingerprint set from 'from' findings
	fromFingerprintSet := make(map[string]*finding.Finding)
	for _, f := range fromFindings {
		fromFingerprintSet[f.Fingerprint().Value()] = f
	}

	// Build fingerprint set from 'to' findings
	toFingerprintSet := make(map[string]*finding.Finding)
	for _, f := range toFindings {
		toFingerprintSet[f.Fingerprint().Value()] = f
	}

	// Find new findings (in 'to' but not in 'from')
	for fp, f := range toFingerprintSet {
		if _, exists := fromFingerprintSet[fp]; !exists {
			output.NewFindings = append(output.NewFindings, f)
			output.Summary.NewBySeverity[f.EffectiveSeverity()]++
		} else {
			output.Unchanged = append(output.Unchanged, f)
		}
	}

	// Find fixed findings (in 'from' but not in 'to')
	for fp, f := range fromFingerprintSet {
		if _, exists := toFingerprintSet[fp]; !exists {
			output.FixedFindings = append(output.FixedFindings, f)
			output.Summary.FixedBySeverity[f.EffectiveSeverity()]++
		}
	}

	// Update summary counts
	output.Summary.TotalNew = len(output.NewFindings)
	output.Summary.TotalFixed = len(output.FixedFindings)
	output.Summary.TotalUnchanged = len(output.Unchanged)
}

// HasNewFindings returns true if new findings were introduced.
func (o DiffRefsOutput) HasNewFindings() bool {
	return len(o.NewFindings) > 0
}

// HasFixedFindings returns true if findings were fixed.
func (o DiffRefsOutput) HasFixedFindings() bool {
	return len(o.FixedFindings) > 0
}

// NetChange returns the net change in findings count.
func (o DiffRefsOutput) NetChange() int {
	return len(o.NewFindings) - len(o.FixedFindings)
}
