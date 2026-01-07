package usecases

import (
	"context"
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/advisory"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/fixer"
)

// ApplyFixInput contains the input for the ApplyFix use case.
type ApplyFixInput struct {
	FindingID string
	DryRun    bool
	NoConfirm bool
	BaseDir   string
}

// ApplyFixOutput contains the output from the ApplyFix use case.
type ApplyFixOutput struct {
	Finding     *finding.Finding
	Remediation *advisory.Remediation
	Results     []*fixer.ApplyResult
	Applied     bool
	Message     string
}

// ApplyFixUseCase handles applying AI-generated fixes to code.
type ApplyFixUseCase struct {
	store   *fixer.Store
	applier *fixer.Applier
	advisor ports.Advisor
}

// NewApplyFixUseCase creates a new ApplyFix use case.
func NewApplyFixUseCase(store *fixer.Store, advisor ports.Advisor) *ApplyFixUseCase {
	return &ApplyFixUseCase{
		store:   store,
		advisor: advisor,
	}
}

// Execute runs the apply fix use case.
func (uc *ApplyFixUseCase) Execute(ctx context.Context, input ApplyFixInput) (*ApplyFixOutput, error) {
	output := &ApplyFixOutput{}

	// Load the finding
	f, err := uc.store.GetFinding(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("failed to find finding: %w", err)
	}
	output.Finding = f

	// Try to get cached remediation first
	rem, err := uc.store.GetRemediation(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("failed to check remediation cache: %w", err)
	}

	// If no cached remediation, generate one
	if rem == nil {
		if uc.advisor == nil || !uc.advisor.IsAvailable() {
			return nil, fmt.Errorf("no cached remediation and AI advisor is not available. Configure AI in .verdict/config.yaml")
		}

		rem, err = uc.advisor.Remediate(ctx, f, ports.RemediationOptions{
			IncludeCode:    true,
			MaxSuggestions: 5,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate remediation: %w", err)
		}

		// Cache the remediation
		if err := uc.store.SaveRemediation(input.FindingID, rem); err != nil {
			// Non-fatal, just warn
			fmt.Printf("Warning: failed to cache remediation: %v\n", err)
		}
	}
	output.Remediation = rem

	// Check if we have code suggestions
	if !rem.HasCodeSuggestions() {
		output.Message = "No code suggestions available for this finding. Manual remediation required."
		return output, nil
	}

	// Create applier
	applierOpts := []fixer.ApplierOption{
		fixer.WithDryRun(input.DryRun),
	}
	if input.BaseDir != "" {
		applierOpts = append(applierOpts, fixer.WithBaseDir(input.BaseDir))
	}
	applier := fixer.NewApplier(applierOpts...)

	// Apply the suggestions
	results, err := applier.ApplyAll(rem.CodeSuggestions())
	if err != nil {
		return nil, fmt.Errorf("failed to apply fixes: %w", err)
	}
	output.Results = results

	// Check results
	allApplied := true
	for _, result := range results {
		if result.Error != nil {
			allApplied = false
		}
	}

	output.Applied = allApplied && !input.DryRun
	if input.DryRun {
		output.Message = "Dry run complete. Use without --dry-run to apply changes."
	} else if allApplied {
		output.Message = fmt.Sprintf("Applied %d fix(es) successfully.", len(results))
	} else {
		output.Message = "Some fixes could not be applied. Check the results for details."
	}

	return output, nil
}

// ListFixableFindings returns findings that have or can have fixes generated.
type ListFixableFindingsInput struct{}

type ListFixableFindingsOutput struct {
	Findings       []*finding.Finding
	HasRemediation map[string]bool
}

// ListFixableFindings lists findings with their remediation status.
func (uc *ApplyFixUseCase) ListFixableFindings(ctx context.Context) (*ListFixableFindingsOutput, error) {
	findings, hasRem, err := uc.store.ListFindings()
	if err != nil {
		return nil, err
	}

	return &ListFixableFindingsOutput{
		Findings:       findings,
		HasRemediation: hasRem,
	}, nil
}

// RollbackInput contains input for the rollback operation.
type RollbackInput struct {
	SnapshotID string
	Latest     bool
	DryRun     bool
}

// RollbackOutput contains the output from a rollback.
type RollbackOutput struct {
	RestoredFiles []string
	Message       string
}

// Rollback restores files from a backup snapshot.
func (uc *ApplyFixUseCase) Rollback(ctx context.Context, input RollbackInput) (*RollbackOutput, error) {
	applier := fixer.NewApplier(fixer.WithDryRun(input.DryRun))

	if input.Latest {
		if input.DryRun {
			latest, err := applier.GetLatestBackup()
			if err != nil {
				return nil, err
			}
			return &RollbackOutput{
				Message: fmt.Sprintf("Would restore from backup: %s", latest),
			}, nil
		}

		if err := applier.RollbackLatest(); err != nil {
			return nil, err
		}

		return &RollbackOutput{
			Message: "Restored files from latest backup.",
		}, nil
	}

	return nil, fmt.Errorf("please specify --latest or a specific snapshot ID")
}

// PreviewFix generates and returns a preview of the fix without applying it.
type PreviewFixInput struct {
	FindingID string
	BaseDir   string
}

type PreviewFixOutput struct {
	Finding     *finding.Finding
	Remediation *advisory.Remediation
	Diffs       []string
}

// PreviewFix generates a preview of what the fix would change.
func (uc *ApplyFixUseCase) PreviewFix(ctx context.Context, input PreviewFixInput) (*PreviewFixOutput, error) {
	result, err := uc.Execute(ctx, ApplyFixInput{
		FindingID: input.FindingID,
		DryRun:    true,
		BaseDir:   input.BaseDir,
	})
	if err != nil {
		return nil, err
	}

	var diffs []string
	for _, r := range result.Results {
		if r.Diff != "" {
			diffs = append(diffs, r.Diff)
		}
	}

	return &PreviewFixOutput{
		Finding:     result.Finding,
		Remediation: result.Remediation,
		Diffs:       diffs,
	}, nil
}
