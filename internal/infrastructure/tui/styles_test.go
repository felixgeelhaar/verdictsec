package tui

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/stretchr/testify/assert"
)

func TestNewStyles_WithColor(t *testing.T) {
	styles := NewStyles(true)

	// Verify styles are initialized and can render
	assert.NotEmpty(t, styles.Critical.Render("TEST"))
	assert.NotEmpty(t, styles.High.Render("TEST"))
	assert.NotEmpty(t, styles.Medium.Render("TEST"))
	assert.NotEmpty(t, styles.Low.Render("TEST"))
}

func TestNewStyles_NoColor(t *testing.T) {
	styles := NewStyles(false)

	// Verify styles are initialized (plain styles)
	assert.NotNil(t, styles.Critical)
	assert.NotNil(t, styles.High)
	assert.NotNil(t, styles.Medium)
	assert.NotNil(t, styles.Low)
}

func TestStyles_SeverityStyle(t *testing.T) {
	styles := NewStyles(true)

	tests := []struct {
		severity finding.Severity
	}{
		{finding.SeverityCritical},
		{finding.SeverityHigh},
		{finding.SeverityMedium},
		{finding.SeverityLow},
		{finding.SeverityUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			style := styles.SeverityStyle(tt.severity)
			assert.NotNil(t, style)
		})
	}
}

func TestStyles_DecisionStyle(t *testing.T) {
	styles := NewStyles(true)

	tests := []struct {
		decision assessment.Decision
	}{
		{assessment.DecisionPass},
		{assessment.DecisionWarn},
		{assessment.DecisionFail},
		{assessment.DecisionUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.decision.String(), func(t *testing.T) {
			style := styles.DecisionStyle(tt.decision)
			assert.NotNil(t, style)
		})
	}
}

func TestStyles_GradeStyle(t *testing.T) {
	styles := NewStyles(true)

	tests := []struct {
		grade services.Grade
	}{
		{services.GradeA},
		{services.GradeB},
		{services.GradeC},
		{services.GradeD},
		{services.GradeF},
	}

	for _, tt := range tests {
		t.Run(string(tt.grade), func(t *testing.T) {
			style := styles.GradeStyle(tt.grade)
			assert.NotNil(t, style)
		})
	}
}

func TestStyles_StatusStyle(t *testing.T) {
	styles := NewStyles(true)

	tests := []struct {
		status string
	}{
		{"new"},
		{"baseline"},
		{"suppressed"},
		{"unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			style := styles.StatusStyle(tt.status)
			assert.NotNil(t, style)
		})
	}
}

func TestStatusIcon(t *testing.T) {
	tests := []struct {
		status   string
		expected string
	}{
		{"new", IconNew},
		{"baseline", IconBaseline},
		{"suppressed", IconSuppressed},
		{"unknown", IconNew}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			result := StatusIcon(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}
