package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

func createTestFinding(severity finding.Severity, ruleID string, detectedAt time.Time) *finding.Finding {
	loc := finding.NewLocation("src/main.go", 10, 1, 10, 20)
	return finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		ruleID,
		"Test finding "+ruleID,
		severity,
		loc,
		finding.WithDetectedAt(detectedAt),
	)
}

func TestTruncationService_NoTruncation(t *testing.T) {
	svc := NewTruncationService()
	now := time.Now()

	findings := []*finding.Finding{
		createTestFinding(finding.SeverityHigh, "G401", now),
		createTestFinding(finding.SeverityMedium, "G402", now),
		createTestFinding(finding.SeverityLow, "G403", now),
	}

	t.Run("MaxFindings zero means no limit", func(t *testing.T) {
		result := svc.Truncate(findings, TruncationConfig{
			MaxFindings: 0,
			Strategy:    StrategyPriority,
		})

		assert.False(t, result.Truncated)
		assert.Equal(t, 3, result.TotalCount)
		assert.Equal(t, 3, result.ShownCount)
		assert.Len(t, result.Findings, 3)
		assert.Empty(t, result.Summary.HiddenBySeverity)
	})

	t.Run("MaxFindings negative means no limit", func(t *testing.T) {
		result := svc.Truncate(findings, TruncationConfig{
			MaxFindings: -1,
			Strategy:    StrategyPriority,
		})

		assert.False(t, result.Truncated)
		assert.Equal(t, 3, result.TotalCount)
		assert.Equal(t, 3, result.ShownCount)
	})

	t.Run("under limit returns all findings", func(t *testing.T) {
		result := svc.Truncate(findings, TruncationConfig{
			MaxFindings: 10,
			Strategy:    StrategyPriority,
		})

		assert.False(t, result.Truncated)
		assert.Equal(t, 3, result.TotalCount)
		assert.Equal(t, 3, result.ShownCount)
		assert.Len(t, result.Findings, 3)
	})

	t.Run("exactly at limit returns all findings", func(t *testing.T) {
		result := svc.Truncate(findings, TruncationConfig{
			MaxFindings: 3,
			Strategy:    StrategyPriority,
		})

		assert.False(t, result.Truncated)
		assert.Equal(t, 3, result.TotalCount)
		assert.Equal(t, 3, result.ShownCount)
	})
}

func TestTruncationService_PriorityStrategy(t *testing.T) {
	svc := NewTruncationService()
	now := time.Now()

	// Create findings with different severities
	findings := []*finding.Finding{
		createTestFinding(finding.SeverityLow, "G001", now),
		createTestFinding(finding.SeverityCritical, "G002", now),
		createTestFinding(finding.SeverityMedium, "G003", now),
		createTestFinding(finding.SeverityHigh, "G004", now),
		createTestFinding(finding.SeverityLow, "G005", now),
		createTestFinding(finding.SeverityHigh, "G006", now),
	}

	result := svc.Truncate(findings, TruncationConfig{
		MaxFindings: 3,
		Strategy:    StrategyPriority,
	})

	require.True(t, result.Truncated)
	assert.Equal(t, 6, result.TotalCount)
	assert.Equal(t, 3, result.ShownCount)
	require.Len(t, result.Findings, 3)

	// Verify order: CRITICAL, HIGH, HIGH (sorted by severity)
	assert.Equal(t, finding.SeverityCritical, result.Findings[0].EffectiveSeverity())
	assert.Equal(t, finding.SeverityHigh, result.Findings[1].EffectiveSeverity())
	assert.Equal(t, finding.SeverityHigh, result.Findings[2].EffectiveSeverity())

	// Verify summary counts
	assert.Equal(t, 1, result.Summary.BySeverity[finding.SeverityCritical])
	assert.Equal(t, 2, result.Summary.BySeverity[finding.SeverityHigh])
	assert.Equal(t, 1, result.Summary.BySeverity[finding.SeverityMedium])
	assert.Equal(t, 2, result.Summary.BySeverity[finding.SeverityLow])

	// Verify hidden counts - MEDIUM and LOW were cut
	assert.Equal(t, 1, result.Summary.HiddenBySeverity[finding.SeverityMedium])
	assert.Equal(t, 2, result.Summary.HiddenBySeverity[finding.SeverityLow])
	assert.Equal(t, 0, result.Summary.HiddenBySeverity[finding.SeverityCritical])
	assert.Equal(t, 0, result.Summary.HiddenBySeverity[finding.SeverityHigh])
}

func TestTruncationService_NewestStrategy(t *testing.T) {
	svc := NewTruncationService()
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Create findings with different times
	findings := []*finding.Finding{
		createTestFinding(finding.SeverityHigh, "G001", baseTime.Add(1*time.Hour)),  // 13:00
		createTestFinding(finding.SeverityHigh, "G002", baseTime.Add(3*time.Hour)),  // 15:00 (newest)
		createTestFinding(finding.SeverityHigh, "G003", baseTime),                   // 12:00 (oldest)
		createTestFinding(finding.SeverityHigh, "G004", baseTime.Add(2*time.Hour)),  // 14:00
	}

	result := svc.Truncate(findings, TruncationConfig{
		MaxFindings: 2,
		Strategy:    StrategyNewest,
	})

	require.True(t, result.Truncated)
	assert.Equal(t, 4, result.TotalCount)
	assert.Equal(t, 2, result.ShownCount)
	require.Len(t, result.Findings, 2)

	// Verify newest findings are kept: G002 (15:00) and G004 (14:00)
	assert.Equal(t, "G002", result.Findings[0].RuleID())
	assert.Equal(t, "G004", result.Findings[1].RuleID())
}

func TestTruncationService_OldestStrategy(t *testing.T) {
	svc := NewTruncationService()
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Create findings with different times
	findings := []*finding.Finding{
		createTestFinding(finding.SeverityHigh, "G001", baseTime.Add(1*time.Hour)),  // 13:00
		createTestFinding(finding.SeverityHigh, "G002", baseTime.Add(3*time.Hour)),  // 15:00 (newest)
		createTestFinding(finding.SeverityHigh, "G003", baseTime),                   // 12:00 (oldest)
		createTestFinding(finding.SeverityHigh, "G004", baseTime.Add(2*time.Hour)),  // 14:00
	}

	result := svc.Truncate(findings, TruncationConfig{
		MaxFindings: 2,
		Strategy:    StrategyOldest,
	})

	require.True(t, result.Truncated)
	assert.Equal(t, 4, result.TotalCount)
	assert.Equal(t, 2, result.ShownCount)
	require.Len(t, result.Findings, 2)

	// Verify oldest findings are kept: G003 (12:00) and G001 (13:00)
	assert.Equal(t, "G003", result.Findings[0].RuleID())
	assert.Equal(t, "G001", result.Findings[1].RuleID())
}

func TestTruncationService_DefaultStrategy(t *testing.T) {
	svc := NewTruncationService()
	now := time.Now()

	findings := []*finding.Finding{
		createTestFinding(finding.SeverityLow, "G001", now),
		createTestFinding(finding.SeverityCritical, "G002", now),
	}

	// Unknown strategy should default to priority
	result := svc.Truncate(findings, TruncationConfig{
		MaxFindings: 1,
		Strategy:    TruncateStrategy("unknown"),
	})

	require.True(t, result.Truncated)
	require.Len(t, result.Findings, 1)
	// Should keep the CRITICAL one (priority behavior)
	assert.Equal(t, finding.SeverityCritical, result.Findings[0].EffectiveSeverity())
}

func TestTruncationService_EmptyFindings(t *testing.T) {
	svc := NewTruncationService()

	result := svc.Truncate([]*finding.Finding{}, TruncationConfig{
		MaxFindings: 10,
		Strategy:    StrategyPriority,
	})

	assert.False(t, result.Truncated)
	assert.Equal(t, 0, result.TotalCount)
	assert.Equal(t, 0, result.ShownCount)
	assert.Empty(t, result.Findings)
}

func TestTruncationService_PreservesInputSlice(t *testing.T) {
	svc := NewTruncationService()
	now := time.Now()

	// Create findings in a specific order
	findings := []*finding.Finding{
		createTestFinding(finding.SeverityLow, "G001", now),
		createTestFinding(finding.SeverityCritical, "G002", now),
		createTestFinding(finding.SeverityMedium, "G003", now),
	}

	// Store original order
	originalOrder := make([]string, len(findings))
	for i, f := range findings {
		originalOrder[i] = f.RuleID()
	}

	// Truncate with priority strategy (will sort)
	_ = svc.Truncate(findings, TruncationConfig{
		MaxFindings: 2,
		Strategy:    StrategyPriority,
	})

	// Verify original slice is unchanged
	for i, f := range findings {
		assert.Equal(t, originalOrder[i], f.RuleID(), "original slice was mutated")
	}
}

func TestTruncationService_StableSort(t *testing.T) {
	svc := NewTruncationService()
	now := time.Now()

	// Create multiple findings with same severity
	findings := []*finding.Finding{
		createTestFinding(finding.SeverityHigh, "G001", now),
		createTestFinding(finding.SeverityHigh, "G002", now),
		createTestFinding(finding.SeverityHigh, "G003", now),
		createTestFinding(finding.SeverityLow, "G004", now),
	}

	result := svc.Truncate(findings, TruncationConfig{
		MaxFindings: 3,
		Strategy:    StrategyPriority,
	})

	require.True(t, result.Truncated)
	require.Len(t, result.Findings, 3)

	// All HIGH findings should be kept in original order (stable sort)
	assert.Equal(t, "G001", result.Findings[0].RuleID())
	assert.Equal(t, "G002", result.Findings[1].RuleID())
	assert.Equal(t, "G003", result.Findings[2].RuleID())
}
