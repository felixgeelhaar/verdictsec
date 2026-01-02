package usecases

import (
	"context"
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// DiffSBOMInput contains the input for SBOM diff.
type DiffSBOMInput struct {
	BasePath   string // Path to base SBOM file
	TargetPath string // Path to target SBOM file
}

// DiffSBOMOutput contains the result of SBOM diff.
type DiffSBOMOutput struct {
	Result services.SBOMDiffResult
	Stats  services.SBOMDiffStats
}

// DiffSBOMUseCase compares two SBOMs and produces a diff.
type DiffSBOMUseCase struct {
	loader      ports.SBOMLoader
	diffService *services.SBOMDiffService
	writer      ports.SBOMDiffWriter
}

// NewDiffSBOMUseCase creates a new SBOM diff use case.
func NewDiffSBOMUseCase(loader ports.SBOMLoader, writer ports.SBOMDiffWriter) *DiffSBOMUseCase {
	return &DiffSBOMUseCase{
		loader:      loader,
		diffService: services.NewSBOMDiffService(),
		writer:      writer,
	}
}

// Execute compares two SBOMs and writes the diff.
func (uc *DiffSBOMUseCase) Execute(ctx context.Context, input DiffSBOMInput) (DiffSBOMOutput, error) {
	// Load base SBOM
	baseSBOM, err := uc.loader.LoadFromFile(ctx, input.BasePath)
	if err != nil {
		return DiffSBOMOutput{}, fmt.Errorf("failed to load base SBOM: %w", err)
	}

	// Load target SBOM
	targetSBOM, err := uc.loader.LoadFromFile(ctx, input.TargetPath)
	if err != nil {
		return DiffSBOMOutput{}, fmt.Errorf("failed to load target SBOM: %w", err)
	}

	// Compute diff
	result := uc.diffService.Diff(baseSBOM, targetSBOM)
	stats := result.Stats()

	// Write output if writer is provided
	if uc.writer != nil {
		if err := uc.writer.Write(result); err != nil {
			return DiffSBOMOutput{}, fmt.Errorf("failed to write diff: %w", err)
		}
	}

	return DiffSBOMOutput{
		Result: result,
		Stats:  stats,
	}, nil
}

// HasChanges returns true if there are any differences.
func (o DiffSBOMOutput) HasChanges() bool {
	return o.Result.HasChanges()
}

// HasMajorChanges returns true if there are major version changes.
func (o DiffSBOMOutput) HasMajorChanges() bool {
	return o.Stats.MajorChanges > 0
}

// HasLicenseChanges returns true if there are license changes.
func (o DiffSBOMOutput) HasLicenseChanges() bool {
	return o.Stats.LicenseChanges > 0
}

// Summary returns a human-readable summary of the diff.
func (o DiffSBOMOutput) Summary() string {
	if !o.HasChanges() {
		return "No changes detected between SBOMs"
	}

	return fmt.Sprintf(
		"Changes: +%d added, -%d removed, ~%d modified (↑%d major, ↗%d minor, →%d patch, 📜%d license)",
		o.Stats.AddedCount,
		o.Stats.RemovedCount,
		o.Stats.ModifiedCount,
		o.Stats.MajorChanges,
		o.Stats.MinorChanges,
		o.Stats.PatchChanges,
		o.Stats.LicenseChanges,
	)
}
