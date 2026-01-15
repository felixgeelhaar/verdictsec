package vex

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewStatement(t *testing.T) {
	products := []string{"pkg:golang/example.com/foo@v1.0.0"}
	stmt := NewStatement(
		"CVE-2024-1234",
		StatusNotAffected,
		JustificationVulnerableCodeNotPresent,
		"The vulnerable code path is not used",
		products,
	)

	assert.Equal(t, "CVE-2024-1234", stmt.VulnID())
	assert.Equal(t, StatusNotAffected, stmt.Status())
	assert.Equal(t, JustificationVulnerableCodeNotPresent, stmt.Justification())
	assert.Equal(t, "The vulnerable code path is not used", stmt.ImpactStatement())
	assert.Equal(t, products, stmt.Products())
	assert.NotZero(t, stmt.Timestamp())
}

func TestStatement_StatusChecks(t *testing.T) {
	tests := []struct {
		name                 string
		status               Status
		isNotAffected        bool
		isAffected           bool
		isFixed              bool
		isUnderInvestigation bool
		shouldSuppress       bool
	}{
		{
			name:          "not_affected",
			status:        StatusNotAffected,
			isNotAffected: true,
			shouldSuppress: true,
		},
		{
			name:           "affected",
			status:         StatusAffected,
			isAffected:     true,
			shouldSuppress: false,
		},
		{
			name:           "fixed",
			status:         StatusFixed,
			isFixed:        true,
			shouldSuppress: true,
		},
		{
			name:                 "under_investigation",
			status:               StatusUnderInvestigation,
			isUnderInvestigation: true,
			shouldSuppress:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := NewStatement("CVE-2024-1234", tt.status, "", "", nil)

			assert.Equal(t, tt.isNotAffected, stmt.IsNotAffected())
			assert.Equal(t, tt.isAffected, stmt.IsAffected())
			assert.Equal(t, tt.isFixed, stmt.IsFixed())
			assert.Equal(t, tt.isUnderInvestigation, stmt.IsUnderInvestigation())
			assert.Equal(t, tt.shouldSuppress, stmt.ShouldSuppress())
		})
	}
}

func TestStatement_AppliesToProduct(t *testing.T) {
	stmt := NewStatement(
		"CVE-2024-1234",
		StatusNotAffected,
		"",
		"",
		[]string{
			"pkg:golang/example.com/foo@v1.0.0",
			"pkg:golang/example.com/bar@v2.0.0",
		},
	)

	assert.True(t, stmt.AppliesToProduct("pkg:golang/example.com/foo@v1.0.0"))
	assert.True(t, stmt.AppliesToProduct("pkg:golang/example.com/bar@v2.0.0"))
	assert.False(t, stmt.AppliesToProduct("pkg:golang/example.com/baz@v1.0.0"))
	assert.False(t, stmt.AppliesToProduct(""))
}

func TestStatement_Setters(t *testing.T) {
	stmt := NewStatement("CVE-2024-1234", StatusAffected, "", "", nil)

	now := time.Now()
	stmt.SetTimestamp(now)
	assert.Equal(t, now, stmt.Timestamp())

	stmt.SetAuthor("security-team")
	assert.Equal(t, "security-team", stmt.Author())

	stmt.SetSupplier("ACME Corp")
	assert.Equal(t, "ACME Corp", stmt.Supplier())

	stmt.SetVersion("1.2.3")
	assert.Equal(t, "1.2.3", stmt.Version())

	stmt.SetActionStatement("Upgrade to v1.2.4")
	assert.Equal(t, "Upgrade to v1.2.4", stmt.ActionStatement())

	subcomponents := []string{"internal/lib"}
	stmt.SetSubcomponents(subcomponents)
	assert.Equal(t, subcomponents, stmt.Subcomponents())
}
