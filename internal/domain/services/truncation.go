package services

import (
	"sort"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// TruncateStrategy defines how findings are truncated when output limits are exceeded.
type TruncateStrategy string

const (
	// StrategyPriority sorts by severity: CRITICAL > HIGH > MEDIUM > LOW.
	StrategyPriority TruncateStrategy = "priority"
	// StrategyNewest sorts by detection time, most recent first.
	StrategyNewest TruncateStrategy = "newest"
	// StrategyOldest sorts by detection time, oldest first.
	StrategyOldest TruncateStrategy = "oldest"
)

// TruncationConfig holds truncation settings.
type TruncationConfig struct {
	MaxFindings int
	Strategy    TruncateStrategy
}

// TruncationResult holds truncated findings and metadata.
type TruncationResult struct {
	Findings   []*finding.Finding
	Truncated  bool
	TotalCount int
	ShownCount int
	Summary    TruncationSummary
}

// TruncationSummary provides counts by severity.
type TruncationSummary struct {
	// BySeverity contains total counts for each severity level.
	BySeverity map[finding.Severity]int
	// HiddenBySeverity contains counts of hidden findings by severity.
	HiddenBySeverity map[finding.Severity]int
}

// TruncationService handles finding truncation for output limits.
// It is a domain service that ensures MCP responses stay within token limits
// while preserving the most important findings.
type TruncationService struct{}

// NewTruncationService creates a new truncation service.
func NewTruncationService() *TruncationService {
	return &TruncationService{}
}

// Truncate applies truncation to findings based on config.
// If MaxFindings is 0 or negative, no truncation is applied.
func (s *TruncationService) Truncate(findings []*finding.Finding, cfg TruncationConfig) TruncationResult {
	totalCount := len(findings)

	// Calculate total counts by severity
	bySeverity := make(map[finding.Severity]int)
	for _, f := range findings {
		bySeverity[f.EffectiveSeverity()]++
	}

	// No truncation needed if MaxFindings is 0/negative or we're under the limit
	if cfg.MaxFindings <= 0 || totalCount <= cfg.MaxFindings {
		return TruncationResult{
			Findings:   findings,
			Truncated:  false,
			TotalCount: totalCount,
			ShownCount: totalCount,
			Summary: TruncationSummary{
				BySeverity:       bySeverity,
				HiddenBySeverity: make(map[finding.Severity]int),
			},
		}
	}

	// Sort findings by strategy
	sorted := s.sortFindings(findings, cfg.Strategy)

	// Take only up to MaxFindings
	truncated := sorted[:cfg.MaxFindings]

	// Calculate hidden counts by severity
	shownBySeverity := make(map[finding.Severity]int)
	for _, f := range truncated {
		shownBySeverity[f.EffectiveSeverity()]++
	}

	hiddenBySeverity := make(map[finding.Severity]int)
	for sev, total := range bySeverity {
		hidden := total - shownBySeverity[sev]
		if hidden > 0 {
			hiddenBySeverity[sev] = hidden
		}
	}

	return TruncationResult{
		Findings:   truncated,
		Truncated:  true,
		TotalCount: totalCount,
		ShownCount: len(truncated),
		Summary: TruncationSummary{
			BySeverity:       bySeverity,
			HiddenBySeverity: hiddenBySeverity,
		},
	}
}

// sortFindings returns a sorted copy of findings based on strategy.
func (s *TruncationService) sortFindings(findings []*finding.Finding, strategy TruncateStrategy) []*finding.Finding {
	// Create a copy to avoid mutating the input
	sorted := make([]*finding.Finding, len(findings))
	copy(sorted, findings)

	switch strategy {
	case StrategyPriority:
		// Sort by severity descending (CRITICAL first, then HIGH, etc.)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].EffectiveSeverity() > sorted[j].EffectiveSeverity()
		})
	case StrategyNewest:
		// Sort by detection time descending (newest first)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].DetectedAt().After(sorted[j].DetectedAt())
		})
	case StrategyOldest:
		// Sort by detection time ascending (oldest first)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].DetectedAt().Before(sorted[j].DetectedAt())
		})
	default:
		// Default to priority strategy
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].EffectiveSeverity() > sorted[j].EffectiveSeverity()
		})
	}

	return sorted
}
