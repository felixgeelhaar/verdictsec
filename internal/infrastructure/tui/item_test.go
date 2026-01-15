package tui

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func createTestFinding(title, ruleID string, severity finding.Severity) *finding.Finding {
	return finding.NewFinding(
		finding.FindingTypeSAST,
		"test-engine",
		ruleID,
		title,
		severity,
		finding.NewLocation("test.go", 10, 5, 10, 50),
		finding.WithDescription("Test description"),
		finding.WithCWE("CWE-89"),
	)
}

func TestFindingItem_Title(t *testing.T) {
	f := createTestFinding("SQL Injection", "sql-inject", finding.SeverityHigh)
	item := FindingItem{
		Finding: f,
		Status:  "new",
	}

	title := item.Title()

	assert.Contains(t, title, "HIGH")
	assert.Contains(t, title, IconNew)
	assert.Contains(t, title, "SQL Injection")
}

func TestFindingItem_Description(t *testing.T) {
	f := createTestFinding("Test Finding", "test-rule", finding.SeverityMedium)
	item := FindingItem{
		Finding: f,
		Status:  "baseline",
	}

	desc := item.Description()

	assert.Contains(t, desc, "test.go")
	assert.Contains(t, desc, "10")
	assert.Contains(t, desc, "test-engine")
}

func TestFindingItem_FilterValue(t *testing.T) {
	f := createTestFinding("SQL Injection", "sql-inject", finding.SeverityHigh)
	item := FindingItem{
		Finding: f,
		Status:  "new",
	}

	filterVal := item.FilterValue()

	assert.Contains(t, filterVal, "SQL Injection")
	assert.Contains(t, filterVal, "test.go")
	assert.Contains(t, filterVal, "sql-inject")
	assert.Contains(t, filterVal, "test-engine")
	assert.Contains(t, filterVal, "CWE-89")
}

func TestFindingItem_SeverityBadge(t *testing.T) {
	tests := []struct {
		severity finding.Severity
		expected string
	}{
		{finding.SeverityCritical, "[CRITICAL]"},
		{finding.SeverityHigh, "[HIGH]"},
		{finding.SeverityMedium, "[MEDIUM]"},
		{finding.SeverityLow, "[LOW]"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			f := createTestFinding("Test", "rule", tt.severity)
			item := FindingItem{Finding: f, Status: "new"}

			badge := item.SeverityBadge()
			assert.Equal(t, tt.expected, badge)
		})
	}
}

func TestFindingItem_StatusString(t *testing.T) {
	tests := []struct {
		status   string
		expected string
	}{
		{"new", "NEW"},
		{"baseline", "BASELINE"},
		{"suppressed", "SUPPRESSED"},
		{"unknown", "UNKNOWN"},
	}

	f := createTestFinding("Test", "rule", finding.SeverityMedium)

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			item := FindingItem{Finding: f, Status: tt.status}
			assert.Equal(t, tt.expected, item.StatusString())
		})
	}
}
