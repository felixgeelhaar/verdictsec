package policy

import (
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func TestDefaultPolicy(t *testing.T) {
	pol := DefaultPolicy()

	assert.Equal(t, "1", pol.Version)
	assert.Equal(t, finding.SeverityHigh, pol.Threshold.FailOn)
	assert.Equal(t, finding.SeverityMedium, pol.Threshold.WarnOn)
	assert.Equal(t, BaselineModeWarn, pol.BaselineMode)
	assert.Empty(t, pol.Suppressions)
}

func TestPolicy_IsSuppressed(t *testing.T) {
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)
	f := finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "Test", finding.SeverityHigh, loc)

	pol := DefaultPolicy()

	// No suppressions
	assert.False(t, pol.IsSuppressed(f))

	// Add suppression by fingerprint
	pol.Suppressions = append(pol.Suppressions, Suppression{
		Fingerprint: f.Fingerprint().Value(),
		Reason:      "Test",
		Owner:       "test@example.com",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	})

	assert.True(t, pol.IsSuppressed(f))
}

func TestPolicy_IsSuppressed_ByRuleID(t *testing.T) {
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)
	f := finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "Test", finding.SeverityHigh, loc)

	pol := DefaultPolicy()
	pol.Suppressions = append(pol.Suppressions, Suppression{
		RuleID:    "G401",
		Reason:    "Accepted risk",
		Owner:     "test@example.com",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	assert.True(t, pol.IsSuppressed(f))
}

func TestPolicy_IsSuppressed_Expired(t *testing.T) {
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)
	f := finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "Test", finding.SeverityHigh, loc)

	pol := DefaultPolicy()
	pol.Suppressions = append(pol.Suppressions, Suppression{
		Fingerprint: f.Fingerprint().Value(),
		Reason:      "Test",
		Owner:       "test@example.com",
		ExpiresAt:   time.Now().Add(-24 * time.Hour), // Expired
	})

	assert.False(t, pol.IsSuppressed(f))
}

func TestPolicy_ActiveSuppressions(t *testing.T) {
	pol := DefaultPolicy()
	pol.Suppressions = []Suppression{
		{Fingerprint: "abc", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(24 * time.Hour)},
		{Fingerprint: "def", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(-24 * time.Hour)}, // Expired
		{Fingerprint: "ghi", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(48 * time.Hour)},
	}

	active := pol.ActiveSuppressions()
	assert.Len(t, active, 2)
}

func TestPolicy_ExpiredSuppressions(t *testing.T) {
	pol := DefaultPolicy()
	pol.Suppressions = []Suppression{
		{Fingerprint: "abc", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(24 * time.Hour)},
		{Fingerprint: "def", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(-24 * time.Hour)},
	}

	expired := pol.ExpiredSuppressions()
	assert.Len(t, expired, 1)
	assert.Equal(t, "def", expired[0].Fingerprint)
}

func TestPolicy_GetThresholdForMode(t *testing.T) {
	pol := DefaultPolicy()
	pol.GatingRules = []GatingRule{
		{
			Mode: ModeCI,
			Threshold: Threshold{
				FailOn: finding.SeverityMedium,
				WarnOn: finding.SeverityLow,
			},
		},
	}

	// CI mode uses specific threshold
	ciThreshold := pol.GetThresholdForMode(ModeCI)
	assert.Equal(t, finding.SeverityMedium, ciThreshold.FailOn)

	// Local mode falls back to default
	localThreshold := pol.GetThresholdForMode(ModeLocal)
	assert.Equal(t, finding.SeverityHigh, localThreshold.FailOn)
}

func TestPolicy_AddSuppression(t *testing.T) {
	pol := DefaultPolicy()

	err := pol.AddSuppression(Suppression{
		Fingerprint: "abc123",
		Reason:      "Test reason",
		Owner:       "test@example.com",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	})

	assert.NoError(t, err)
	assert.Len(t, pol.Suppressions, 1)
}

func TestPolicy_AddSuppression_Invalid(t *testing.T) {
	pol := DefaultPolicy()

	err := pol.AddSuppression(Suppression{
		Fingerprint: "abc123",
		// Missing reason
		Owner:     "test@example.com",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	assert.Error(t, err)
}

func TestPolicy_RemoveSuppression(t *testing.T) {
	pol := DefaultPolicy()
	pol.Suppressions = []Suppression{
		{Fingerprint: "abc", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(24 * time.Hour)},
		{Fingerprint: "def", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(24 * time.Hour)},
	}

	removed := pol.RemoveSuppression("abc", "")
	assert.True(t, removed)
	assert.Len(t, pol.Suppressions, 1)
	assert.Equal(t, "def", pol.Suppressions[0].Fingerprint)

	// Try to remove non-existent
	removed = pol.RemoveSuppression("xyz", "")
	assert.False(t, removed)
}

func TestPolicy_CleanupExpired(t *testing.T) {
	pol := DefaultPolicy()
	pol.Suppressions = []Suppression{
		{Fingerprint: "abc", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(24 * time.Hour)},
		{Fingerprint: "def", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(-24 * time.Hour)},
		{Fingerprint: "ghi", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(-48 * time.Hour)},
	}

	count := pol.CleanupExpired()
	assert.Equal(t, 2, count)
	assert.Len(t, pol.Suppressions, 1)
}

func TestPolicy_Validate(t *testing.T) {
	pol := DefaultPolicy()
	assert.NoError(t, pol.Validate())

	// Invalid baseline mode
	pol.BaselineMode = "invalid"
	assert.Error(t, pol.Validate())
}

func TestPolicy_GetSuppression(t *testing.T) {
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)
	f := finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "Test", finding.SeverityHigh, loc)

	pol := DefaultPolicy()
	pol.Suppressions = append(pol.Suppressions, Suppression{
		Fingerprint: f.Fingerprint().Value(),
		Reason:      "Test reason",
		Owner:       "test@example.com",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	})

	supp := pol.GetSuppression(f)
	assert.NotNil(t, supp)
	assert.Equal(t, "Test reason", supp.Reason)

	// Non-matching finding
	f2 := finding.NewFinding(finding.FindingTypeSAST, "gosec", "G402", "Test", finding.SeverityHigh, loc)
	supp = pol.GetSuppression(f2)
	assert.Nil(t, supp)
}

func TestPolicy_Counts(t *testing.T) {
	pol := DefaultPolicy()
	pol.Suppressions = []Suppression{
		{Fingerprint: "abc", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(24 * time.Hour)},
		{Fingerprint: "def", Reason: "R", Owner: "O", ExpiresAt: time.Now().Add(-24 * time.Hour)},
	}

	assert.Equal(t, 2, pol.SuppressionCount())
	assert.Equal(t, 1, pol.ActiveSuppressionCount())
}
