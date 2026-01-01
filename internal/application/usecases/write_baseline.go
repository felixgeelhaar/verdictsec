package usecases

import (
	"fmt"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// WriteBaselineInput contains input for creating a new baseline.
type WriteBaselineInput struct {
	Assessment *assessment.Assessment
	Target     string
	Path       string // Optional: override default path
	Reason     string // Required: reason for baselining
}

// WriteBaselineOutput contains the result of baseline creation.
type WriteBaselineOutput struct {
	Baseline     *baseline.Baseline
	EntriesAdded int
	Path         string
}

// UpdateBaselineInput contains input for updating an existing baseline.
type UpdateBaselineInput struct {
	Assessment     *assessment.Assessment
	Baseline       *baseline.Baseline
	PruneAfterDays int    // 0 = don't prune
	Reason         string // Required: reason for baselining new findings
}

// UpdateBaselineOutput contains the result of baseline update.
type UpdateBaselineOutput struct {
	Baseline       *baseline.Baseline
	EntriesAdded   int
	EntriesUpdated int
	EntriesPruned  int
}

// WriteBaselineUseCase manages baseline creation and updates.
type WriteBaselineUseCase struct {
	store  ports.BaselineStore
	writer ports.ArtifactWriter
}

// NewWriteBaselineUseCase creates a new baseline management use case.
func NewWriteBaselineUseCase(store ports.BaselineStore, writer ports.ArtifactWriter) *WriteBaselineUseCase {
	return &WriteBaselineUseCase{
		store:  store,
		writer: writer,
	}
}

// Write creates a new baseline from assessment findings.
func (uc *WriteBaselineUseCase) Write(input WriteBaselineInput) (WriteBaselineOutput, error) {
	output := WriteBaselineOutput{}

	// Validate reason is provided
	if input.Reason == "" {
		return output, fmt.Errorf("reason is required for baselining findings")
	}

	// Create new baseline
	b := baseline.NewBaseline(input.Target)

	// Add all findings with reason
	findings := input.Assessment.Findings()
	if err := b.AddAll(findings, input.Reason); err != nil {
		return output, err
	}

	output.Baseline = b
	output.EntriesAdded = len(findings)

	// Save baseline
	var err error
	if input.Path != "" {
		err = uc.store.SaveTo(b, input.Path)
		output.Path = input.Path
	} else {
		err = uc.store.Save(b)
		output.Path = uc.store.DefaultPath()
	}

	if err != nil {
		return output, fmt.Errorf("failed to save baseline: %w", err)
	}

	// Report
	if uc.writer != nil {
		_ = uc.writer.WriteProgress(fmt.Sprintf("Baseline created with %d entries: %s", output.EntriesAdded, output.Path))
	}

	return output, nil
}

// Update merges new findings into an existing baseline.
func (uc *WriteBaselineUseCase) Update(input UpdateBaselineInput) (UpdateBaselineOutput, error) {
	output := UpdateBaselineOutput{
		Baseline: input.Baseline,
	}

	if input.Baseline == nil {
		return output, fmt.Errorf("baseline is nil")
	}

	// Validate reason is provided
	if input.Reason == "" {
		return output, fmt.Errorf("reason is required for baselining findings")
	}

	findings := input.Assessment.Findings()
	existingCount := input.Baseline.Count()

	// Track which fingerprints are new
	newFingerprints := make(map[string]bool)
	for _, f := range findings {
		fp := f.Fingerprint().Value()
		if !input.Baseline.ContainsFingerprint(fp) {
			newFingerprints[fp] = true
		}
	}

	// Add/update findings with reason
	if err := input.Baseline.AddAll(findings, input.Reason); err != nil {
		return output, err
	}

	output.EntriesAdded = len(newFingerprints)
	output.EntriesUpdated = len(findings) - len(newFingerprints)

	// Prune stale entries if requested
	if input.PruneAfterDays > 0 {
		threshold := time.Duration(input.PruneAfterDays) * 24 * time.Hour
		output.EntriesPruned = input.Baseline.RemoveStale(threshold)
	}

	// Save baseline
	if err := uc.store.Save(input.Baseline); err != nil {
		return output, fmt.Errorf("failed to save baseline: %w", err)
	}

	// Report
	if uc.writer != nil {
		msg := fmt.Sprintf("Baseline updated: +%d new, ~%d updated",
			output.EntriesAdded, output.EntriesUpdated)
		if output.EntriesPruned > 0 {
			msg += fmt.Sprintf(", -%d pruned", output.EntriesPruned)
		}
		msg += fmt.Sprintf(" (total: %d → %d)", existingCount, input.Baseline.Count())
		_ = uc.writer.WriteProgress(msg)
	}

	return output, nil
}

// MergeInput contains input for merging baselines.
type MergeInput struct {
	Target  *baseline.Baseline
	Sources []*baseline.Baseline
}

// MergeOutput contains the result of baseline merge.
type MergeOutput struct {
	Baseline    *baseline.Baseline
	TotalMerged int
}

// Merge combines multiple baselines into one.
func (uc *WriteBaselineUseCase) Merge(input MergeInput) (MergeOutput, error) {
	output := MergeOutput{
		Baseline: input.Target,
	}

	if input.Target == nil {
		return output, fmt.Errorf("target baseline is nil")
	}

	for _, source := range input.Sources {
		if source != nil {
			beforeCount := input.Target.Count()
			input.Target.Merge(source)
			output.TotalMerged += input.Target.Count() - beforeCount
		}
	}

	// Save merged baseline
	if err := uc.store.Save(input.Target); err != nil {
		return output, fmt.Errorf("failed to save merged baseline: %w", err)
	}

	return output, nil
}

// FilterInput contains input for filtering a baseline.
type FilterInput struct {
	Baseline    *baseline.Baseline
	MinSeverity finding.Severity
	EngineIDs   []string
}

// FilterOutput contains the result of baseline filtering.
type FilterOutput struct {
	Baseline       *baseline.Baseline
	EntriesRemoved int
}

// Filter removes entries that don't match criteria.
func (uc *WriteBaselineUseCase) Filter(input FilterInput) (FilterOutput, error) {
	output := FilterOutput{}

	if input.Baseline == nil {
		return output, fmt.Errorf("baseline is nil")
	}

	// Clone to avoid modifying original
	filtered := input.Baseline.Clone()
	originalCount := filtered.Count()

	// Filter by engine if specified
	if len(input.EngineIDs) > 0 {
		engineSet := make(map[string]bool)
		for _, id := range input.EngineIDs {
			engineSet[id] = true
		}

		for _, fp := range filtered.Fingerprints() {
			entry := filtered.GetEntryByFingerprint(fp)
			if entry != nil && !engineSet[entry.EngineID] {
				filtered.Remove(fp)
			}
		}
	}

	output.Baseline = filtered
	output.EntriesRemoved = originalCount - filtered.Count()

	return output, nil
}

// LoadOrCreate loads an existing baseline or creates a new one.
func (uc *WriteBaselineUseCase) LoadOrCreate(target string) (*baseline.Baseline, error) {
	if uc.store.Exists() {
		return uc.store.Load()
	}
	return baseline.NewBaseline(target), nil
}
