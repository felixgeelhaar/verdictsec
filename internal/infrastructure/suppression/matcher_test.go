package suppression

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

func createTestFinding(file string, line int, ruleID string) *finding.Finding {
	loc := finding.NewLocationSimple(file, line)
	return finding.NewFinding(
		finding.FindingTypeSAST,
		"test-engine",
		ruleID,
		"Test finding",
		finding.SeverityMedium,
		loc,
	)
}

func TestMatcher_Match(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "main.go", Line: 5, RuleIDs: []string{"G101"}, Scope: ScopeLine},
		{File: "util.go", Line: 1, RuleIDs: []string{"G201"}, Scope: ScopeFile},
		{File: "db.go", Line: 10, RuleIDs: []string{"G301"}, Scope: ScopeBlock, EffectiveEnd: 15},
	}
	set := NewSuppressionSet(suppressions)
	matcher := NewMatcher(set, "")

	tests := []struct {
		name       string
		file       string
		line       int
		ruleID     string
		suppressed bool
	}{
		{"line - suppressed", "main.go", 6, "G101", true},
		{"line - wrong line", "main.go", 7, "G101", false},
		{"line - wrong rule", "main.go", 6, "G102", false},
		{"file - suppressed", "util.go", 50, "G201", true},
		{"file - wrong rule", "util.go", 50, "G999", false},
		{"block - in block", "db.go", 12, "G301", true},
		{"block - after block", "db.go", 20, "G301", false},
		{"no match", "other.go", 1, "G101", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := createTestFinding(tt.file, tt.line, tt.ruleID)
			result := matcher.Match(f)

			if result.Suppressed != tt.suppressed {
				t.Errorf("Match() suppressed = %v, want %v", result.Suppressed, tt.suppressed)
			}

			if tt.suppressed && result.Suppression == nil {
				t.Error("Expected suppression details when suppressed")
			}
		})
	}
}

func TestMatcher_NilSet(t *testing.T) {
	matcher := NewMatcher(nil, "")
	f := createTestFinding("main.go", 6, "G101")

	result := matcher.Match(f)
	if result.Suppressed {
		t.Error("Expected not suppressed with nil set")
	}
}

func TestMatcher_NilFinding(t *testing.T) {
	set := NewSuppressionSet([]InlineSuppression{})
	matcher := NewMatcher(set, "")

	result := matcher.Match(nil)
	if result.Suppressed {
		t.Error("Expected not suppressed with nil finding")
	}
}

func TestMatcher_FilterSuppressed(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "main.go", Line: 5, RuleIDs: []string{"G101"}, Scope: ScopeLine},
	}
	set := NewSuppressionSet(suppressions)
	matcher := NewMatcher(set, "")

	findings := []*finding.Finding{
		createTestFinding("main.go", 6, "G101"),  // suppressed
		createTestFinding("main.go", 10, "G101"), // not suppressed
		createTestFinding("main.go", 6, "G102"),  // not suppressed (different rule)
	}

	filtered := matcher.FilterSuppressed(findings)

	if len(filtered) != 2 {
		t.Errorf("Expected 2 unsuppressed findings, got %d", len(filtered))
	}
}

func TestMatcher_GetSuppressed(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "main.go", Line: 5, RuleIDs: []string{"G101"}, Scope: ScopeLine},
	}
	set := NewSuppressionSet(suppressions)
	matcher := NewMatcher(set, "")

	findings := []*finding.Finding{
		createTestFinding("main.go", 6, "G101"),  // suppressed
		createTestFinding("main.go", 10, "G101"), // not suppressed
	}

	suppressed := matcher.GetSuppressed(findings)

	if len(suppressed) != 1 {
		t.Errorf("Expected 1 suppressed finding, got %d", len(suppressed))
	}
}

func TestMatcher_PartitionFindings(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "main.go", Line: 5, RuleIDs: []string{"G101"}, Scope: ScopeLine},
		{File: "util.go", Line: 1, RuleIDs: []string{"G201"}, Scope: ScopeFile},
	}
	set := NewSuppressionSet(suppressions)
	matcher := NewMatcher(set, "")

	findings := []*finding.Finding{
		createTestFinding("main.go", 6, "G101"),  // suppressed
		createTestFinding("main.go", 10, "G101"), // not suppressed
		createTestFinding("util.go", 50, "G201"), // suppressed
		createTestFinding("other.go", 1, "G301"), // not suppressed
	}

	suppressed, unsuppressed := matcher.PartitionFindings(findings)

	if len(suppressed) != 2 {
		t.Errorf("Expected 2 suppressed findings, got %d", len(suppressed))
	}
	if len(unsuppressed) != 2 {
		t.Errorf("Expected 2 unsuppressed findings, got %d", len(unsuppressed))
	}
}

func TestMatcher_GetStats(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "main.go", Line: 5, RuleIDs: []string{"G101"}, Scope: ScopeLine},
		{File: "util.go", Line: 1, RuleIDs: []string{"G201"}, Scope: ScopeFile},
	}
	set := NewSuppressionSet(suppressions)
	matcher := NewMatcher(set, "")

	findings := []*finding.Finding{
		createTestFinding("main.go", 6, "G101"),  // suppressed by line
		createTestFinding("util.go", 50, "G201"), // suppressed by file
		createTestFinding("other.go", 1, "G301"), // not suppressed
	}

	stats := matcher.GetStats(findings)

	if stats.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", stats.TotalFindings)
	}
	if stats.SuppressedCount != 2 {
		t.Errorf("Expected 2 suppressed, got %d", stats.SuppressedCount)
	}
	if stats.UnsuppressedCount != 1 {
		t.Errorf("Expected 1 unsuppressed, got %d", stats.UnsuppressedCount)
	}
	if stats.SuppressionsByScope[ScopeLine] != 1 {
		t.Errorf("Expected 1 line suppression, got %d", stats.SuppressionsByScope[ScopeLine])
	}
	if stats.SuppressionsByScope[ScopeFile] != 1 {
		t.Errorf("Expected 1 file suppression, got %d", stats.SuppressionsByScope[ScopeFile])
	}
}

func TestMatcher_NormalizeFilePath(t *testing.T) {
	set := NewSuppressionSet([]InlineSuppression{})
	matcher := NewMatcher(set, "/project")

	tests := []struct {
		input    string
		expected string
	}{
		{"main.go", "main.go"},
		{"./main.go", "main.go"},
		{"/project/main.go", "main.go"},
		{"/project/internal/app.go", "internal/app.go"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := matcher.normalizeFilePath(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeFilePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMatcher_MatchAll(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "main.go", Line: 5, RuleIDs: []string{"G101"}, Scope: ScopeLine},
	}
	set := NewSuppressionSet(suppressions)
	matcher := NewMatcher(set, "")

	findings := []*finding.Finding{
		createTestFinding("main.go", 6, "G101"),
		createTestFinding("main.go", 10, "G101"),
	}

	results := matcher.MatchAll(findings)

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
	if !results[0].Suppressed {
		t.Error("Expected first finding to be suppressed")
	}
	if results[1].Suppressed {
		t.Error("Expected second finding to not be suppressed")
	}
}

func TestInlineSuppressionService_QuickFilter(t *testing.T) {
	// This test would require creating actual files
	// For unit testing, we just verify the service creates properly
	service := NewInlineSuppressionService()
	if service == nil {
		t.Fatal("Expected non-nil service")
	}
	if service.parser == nil {
		t.Error("Expected non-nil parser")
	}
}
