package services

import (
	"github.com/felixgeelhaar/verdictsec/internal/domain/sbom"
)

// SBOMDiffResult contains the comparison between two SBOMs.
type SBOMDiffResult struct {
	Base   *sbom.SBOM // Base SBOM (older)
	Target *sbom.SBOM // Target SBOM (newer)

	Added    []sbom.Component // Components in target but not in base
	Removed  []sbom.Component // Components in base but not in target
	Modified []ComponentDiff  // Components with version or license changes
	Unchanged []sbom.Component // Components that are identical
}

// ComponentDiff represents a changed component.
type ComponentDiff struct {
	Base          sbom.Component     // Original component
	Target        sbom.Component     // Modified component
	VersionChange sbom.VersionChange // Type of version change
	LicenseChange bool               // True if license changed
}

// SBOMDiffService computes differences between two SBOMs.
type SBOMDiffService struct{}

// NewSBOMDiffService creates a new SBOM diff service.
func NewSBOMDiffService() *SBOMDiffService {
	return &SBOMDiffService{}
}

// Diff compares two SBOMs and returns the differences.
// Base is the older SBOM, target is the newer SBOM.
func (s *SBOMDiffService) Diff(base, target *sbom.SBOM) SBOMDiffResult {
	result := SBOMDiffResult{
		Base:      base,
		Target:    target,
		Added:     []sbom.Component{},
		Removed:   []sbom.Component{},
		Modified:  []ComponentDiff{},
		Unchanged: []sbom.Component{},
	}

	if base == nil || target == nil {
		if base == nil && target != nil {
			result.Added = target.Components()
		} else if base != nil && target == nil {
			result.Removed = base.Components()
		}
		return result
	}

	// Build maps for efficient lookup (key without version)
	baseMap := base.ComponentMap()
	targetMap := target.ComponentMap()

	// Find added and modified components
	for key, targetComp := range targetMap {
		baseComp, exists := baseMap[key]
		if !exists {
			result.Added = append(result.Added, targetComp)
		} else {
			// Component exists in both - check for changes
			versionChange := sbom.CompareVersion(baseComp.Version(), targetComp.Version())
			licenseChange := baseComp.License() != targetComp.License()

			if versionChange != sbom.VersionUnchanged || licenseChange {
				result.Modified = append(result.Modified, ComponentDiff{
					Base:          baseComp,
					Target:        targetComp,
					VersionChange: versionChange,
					LicenseChange: licenseChange,
				})
			} else {
				result.Unchanged = append(result.Unchanged, targetComp)
			}
		}
	}

	// Find removed components
	for key, baseComp := range baseMap {
		if _, exists := targetMap[key]; !exists {
			result.Removed = append(result.Removed, baseComp)
		}
	}

	return result
}

// SBOMDiffStats provides statistics about an SBOM diff.
type SBOMDiffStats struct {
	AddedCount     int
	RemovedCount   int
	ModifiedCount  int
	UnchangedCount int

	// Breakdown of version changes
	MajorChanges int
	MinorChanges int
	PatchChanges int
	OtherChanges int

	// License changes
	LicenseChanges int
}

// Stats returns statistics about the diff result.
func (r SBOMDiffResult) Stats() SBOMDiffStats {
	stats := SBOMDiffStats{
		AddedCount:     len(r.Added),
		RemovedCount:   len(r.Removed),
		ModifiedCount:  len(r.Modified),
		UnchangedCount: len(r.Unchanged),
	}

	for _, diff := range r.Modified {
		switch diff.VersionChange {
		case sbom.VersionMajor:
			stats.MajorChanges++
		case sbom.VersionMinor:
			stats.MinorChanges++
		case sbom.VersionPatch:
			stats.PatchChanges++
		case sbom.VersionOther:
			stats.OtherChanges++
		}

		if diff.LicenseChange {
			stats.LicenseChanges++
		}
	}

	return stats
}

// HasChanges returns true if there are any differences.
func (r SBOMDiffResult) HasChanges() bool {
	return len(r.Added) > 0 || len(r.Removed) > 0 || len(r.Modified) > 0
}

// TotalBase returns the total component count in the base SBOM.
func (r SBOMDiffResult) TotalBase() int {
	if r.Base == nil {
		return 0
	}
	return r.Base.ComponentCount()
}

// TotalTarget returns the total component count in the target SBOM.
func (r SBOMDiffResult) TotalTarget() int {
	if r.Target == nil {
		return 0
	}
	return r.Target.ComponentCount()
}

// MajorVersionChanges returns only components with major version changes.
func (r SBOMDiffResult) MajorVersionChanges() []ComponentDiff {
	var result []ComponentDiff
	for _, d := range r.Modified {
		if d.VersionChange == sbom.VersionMajor {
			result = append(result, d)
		}
	}
	return result
}

// LicenseChanges returns only components with license changes.
func (r SBOMDiffResult) LicenseChangesOnly() []ComponentDiff {
	var result []ComponentDiff
	for _, d := range r.Modified {
		if d.LicenseChange {
			result = append(result, d)
		}
	}
	return result
}
