package services

import (
	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// DiffResult contains the comparison between current findings and baseline.
type DiffResult struct {
	New      []*finding.Finding // In current, not in baseline
	Existing []*finding.Finding // In both current and baseline
	Resolved []string           // In baseline, not in current (fingerprints)
}

// DiffService computes finding differences against a baseline.
// It is a domain service that enables "fail only on new" behavior.
type DiffService struct{}

// NewDiffService creates a new diff service.
func NewDiffService() *DiffService {
	return &DiffService{}
}

// Diff compares current findings against a baseline.
// Returns categorized findings: new, existing, and resolved.
func (s *DiffService) Diff(
	current []*finding.Finding,
	base *baseline.Baseline,
) DiffResult {
	result := DiffResult{
		New:      []*finding.Finding{},
		Existing: []*finding.Finding{},
		Resolved: []string{},
	}

	if base == nil {
		// No baseline means everything is new
		result.New = current
		return result
	}

	// Track which baseline entries we've seen
	seen := make(map[string]bool)

	for _, f := range current {
		fp := f.Fingerprint().Value()
		if base.ContainsFingerprint(fp) {
			result.Existing = append(result.Existing, f)
			seen[fp] = true
		} else {
			result.New = append(result.New, f)
		}
	}

	// Find resolved (in baseline but not in current)
	for _, fp := range base.Fingerprints() {
		if !seen[fp] {
			result.Resolved = append(result.Resolved, fp)
		}
	}

	return result
}

// DiffStats provides statistics about the diff.
type DiffStats struct {
	NewCount      int
	ExistingCount int
	ResolvedCount int
}

// Stats returns statistics about a diff result.
func (r DiffResult) Stats() DiffStats {
	return DiffStats{
		NewCount:      len(r.New),
		ExistingCount: len(r.Existing),
		ResolvedCount: len(r.Resolved),
	}
}

// HasNew returns true if there are new findings.
func (r DiffResult) HasNew() bool {
	return len(r.New) > 0
}

// HasResolved returns true if there are resolved findings.
func (r DiffResult) HasResolved() bool {
	return len(r.Resolved) > 0
}

// TotalCurrent returns the total number of current findings.
func (r DiffResult) TotalCurrent() int {
	return len(r.New) + len(r.Existing)
}

// NewBySeverity returns new findings filtered by minimum severity.
func (r DiffResult) NewBySeverity(minSeverity finding.Severity) []*finding.Finding {
	var result []*finding.Finding
	for _, f := range r.New {
		if f.EffectiveSeverity().IsAtLeast(minSeverity) {
			result = append(result, f)
		}
	}
	return result
}

// NewByType returns new findings filtered by type.
func (r DiffResult) NewByType(t finding.FindingType) []*finding.Finding {
	var result []*finding.Finding
	for _, f := range r.New {
		if f.Type() == t {
			result = append(result, f)
		}
	}
	return result
}
