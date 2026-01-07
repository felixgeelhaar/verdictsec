package suppression

import (
	"path/filepath"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// MatchResult represents the result of matching a finding against inline suppressions.
type MatchResult struct {
	Finding     *finding.Finding
	Suppressed  bool
	Suppression *InlineSuppression
}

// Matcher matches findings against inline suppressions.
type Matcher struct {
	set      *SuppressionSet
	basePath string
}

// NewMatcher creates a new suppression matcher.
func NewMatcher(set *SuppressionSet, basePath string) *Matcher {
	return &Matcher{
		set:      set,
		basePath: basePath,
	}
}

// Match checks if a finding is suppressed by an inline comment.
func (m *Matcher) Match(f *finding.Finding) MatchResult {
	result := MatchResult{
		Finding:    f,
		Suppressed: false,
	}

	if m.set == nil || f == nil {
		return result
	}

	// Get file path relative to base
	filePath := m.normalizeFilePath(f.Location().File())
	line := f.Location().Line()
	ruleID := f.RuleID()

	// Check if suppressed
	if m.set.IsSuppressed(filePath, line, ruleID) {
		result.Suppressed = true
		result.Suppression = m.set.GetSuppression(filePath, line, ruleID)
	}

	return result
}

// MatchAll checks all findings against the suppression set.
func (m *Matcher) MatchAll(findings []*finding.Finding) []MatchResult {
	results := make([]MatchResult, len(findings))
	for i, f := range findings {
		results[i] = m.Match(f)
	}
	return results
}

// FilterSuppressed returns findings that are NOT suppressed.
func (m *Matcher) FilterSuppressed(findings []*finding.Finding) []*finding.Finding {
	var result []*finding.Finding
	for _, f := range findings {
		if !m.Match(f).Suppressed {
			result = append(result, f)
		}
	}
	return result
}

// GetSuppressed returns findings that ARE suppressed.
func (m *Matcher) GetSuppressed(findings []*finding.Finding) []*finding.Finding {
	var result []*finding.Finding
	for _, f := range findings {
		if m.Match(f).Suppressed {
			result = append(result, f)
		}
	}
	return result
}

// PartitionFindings separates findings into suppressed and unsuppressed.
func (m *Matcher) PartitionFindings(findings []*finding.Finding) (suppressed, unsuppressed []*finding.Finding) {
	for _, f := range findings {
		if m.Match(f).Suppressed {
			suppressed = append(suppressed, f)
		} else {
			unsuppressed = append(unsuppressed, f)
		}
	}
	return
}

// normalizeFilePath makes the file path relative and consistent.
func (m *Matcher) normalizeFilePath(filePath string) string {
	// Already relative
	if !filepath.IsAbs(filePath) {
		return filepath.Clean(filePath)
	}

	// Try to make relative to base path
	if m.basePath != "" {
		if rel, err := filepath.Rel(m.basePath, filePath); err == nil {
			return filepath.Clean(rel)
		}
	}

	// Strip common prefixes
	filePath = filepath.Clean(filePath)

	// Try to find a relative path by looking for common patterns
	parts := strings.Split(filePath, string(filepath.Separator))
	for i, part := range parts {
		// Look for typical project root indicators
		if part == "internal" || part == "cmd" || part == "pkg" || part == "main.go" {
			return filepath.Join(parts[i:]...)
		}
	}

	return filePath
}

// SuppressionStats provides statistics about suppression matching.
type SuppressionStats struct {
	TotalFindings        int
	SuppressedCount      int
	UnsuppressedCount    int
	SuppressionsByScope  map[Scope]int
	SuppressionsByRule   map[string]int
}

// GetStats returns statistics about how suppressions were applied.
func (m *Matcher) GetStats(findings []*finding.Finding) SuppressionStats {
	stats := SuppressionStats{
		TotalFindings:       len(findings),
		SuppressionsByScope: make(map[Scope]int),
		SuppressionsByRule:  make(map[string]int),
	}

	for _, f := range findings {
		result := m.Match(f)
		if result.Suppressed {
			stats.SuppressedCount++
			if result.Suppression != nil {
				stats.SuppressionsByScope[result.Suppression.Scope]++
				for _, ruleID := range result.Suppression.RuleIDs {
					stats.SuppressionsByRule[ruleID]++
				}
			}
		} else {
			stats.UnsuppressedCount++
		}
	}

	return stats
}

// InlineSuppressionService coordinates parsing and matching of inline suppressions.
type InlineSuppressionService struct {
	parser *Parser
}

// NewInlineSuppressionService creates a new inline suppression service.
func NewInlineSuppressionService() *InlineSuppressionService {
	return &InlineSuppressionService{
		parser: NewParser(),
	}
}

// ParseAndMatch parses a directory for suppressions and matches findings.
func (s *InlineSuppressionService) ParseAndMatch(targetDir string, findings []*finding.Finding) (*Matcher, error) {
	// Parse all suppressions from the directory
	suppressions, err := s.parser.ParseDirectory(targetDir)
	if err != nil {
		return nil, err
	}

	// Create suppression set
	set := NewSuppressionSet(suppressions)

	// Create and return matcher
	return NewMatcher(set, targetDir), nil
}

// QuickFilter parses and filters in one call.
func (s *InlineSuppressionService) QuickFilter(targetDir string, findings []*finding.Finding) ([]*finding.Finding, []*finding.Finding, error) {
	matcher, err := s.ParseAndMatch(targetDir, findings)
	if err != nil {
		return findings, nil, err // Return all findings if parsing fails
	}

	suppressed, unsuppressed := matcher.PartitionFindings(findings)
	return unsuppressed, suppressed, nil
}
