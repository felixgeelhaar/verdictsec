package policy

import (
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func TestNewSuppression(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	s := NewSuppression("abc123", "", "Test reason", "test@example.com", expiresAt)

	assert.Equal(t, "abc123", s.Fingerprint)
	assert.Empty(t, s.RuleID)
	assert.Equal(t, "Test reason", s.Reason)
	assert.Equal(t, "test@example.com", s.Owner)
	assert.False(t, s.CreatedAt.IsZero())
}

func TestSuppression_IsExpired(t *testing.T) {
	// Not expired
	s := NewSuppression("abc", "", "R", "O", time.Now().Add(24*time.Hour))
	assert.False(t, s.IsExpired())
	assert.True(t, s.IsActive())

	// Expired
	s = NewSuppression("abc", "", "R", "O", time.Now().Add(-24*time.Hour))
	assert.True(t, s.IsExpired())
	assert.False(t, s.IsActive())
}

func TestSuppression_Matches(t *testing.T) {
	loc := finding.NewLocation("main.go", 10, 5, 10, 20)
	f := finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "Test", finding.SeverityHigh, loc)

	// Match by fingerprint
	s := &Suppression{Fingerprint: f.Fingerprint().Value()}
	assert.True(t, s.Matches(f))

	// Match by rule ID
	s = &Suppression{RuleID: "G401"}
	assert.True(t, s.Matches(f))

	// No match
	s = &Suppression{RuleID: "G999"}
	assert.False(t, s.Matches(f))

	// Empty suppression
	s = &Suppression{}
	assert.False(t, s.Matches(f))
}

func TestSuppression_DaysUntilExpiry(t *testing.T) {
	// 10 days until expiry
	s := NewSuppression("abc", "", "R", "O", time.Now().Add(10*24*time.Hour))
	days := s.DaysUntilExpiry()
	assert.GreaterOrEqual(t, days, 9)
	assert.LessOrEqual(t, days, 10)

	// Already expired
	s = NewSuppression("abc", "", "R", "O", time.Now().Add(-24*time.Hour))
	assert.Equal(t, 0, s.DaysUntilExpiry())
}

func TestSuppression_Validate(t *testing.T) {
	tests := []struct {
		name      string
		s         Suppression
		expectErr bool
	}{
		{
			name: "valid with fingerprint",
			s: Suppression{
				Fingerprint: "abc123",
				Reason:      "Test",
				Owner:       "test@example.com",
				ExpiresAt:   time.Now().Add(24 * time.Hour),
			},
			expectErr: false,
		},
		{
			name: "valid with rule ID",
			s: Suppression{
				RuleID:    "G401",
				Reason:    "Test",
				Owner:     "test@example.com",
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			expectErr: false,
		},
		{
			name: "missing reason",
			s: Suppression{
				Fingerprint: "abc123",
				Owner:       "test@example.com",
				ExpiresAt:   time.Now().Add(24 * time.Hour),
			},
			expectErr: true,
		},
		{
			name: "missing owner",
			s: Suppression{
				Fingerprint: "abc123",
				Reason:      "Test",
				ExpiresAt:   time.Now().Add(24 * time.Hour),
			},
			expectErr: true,
		},
		{
			name: "missing expiry",
			s: Suppression{
				Fingerprint: "abc123",
				Reason:      "Test",
				Owner:       "test@example.com",
			},
			expectErr: true,
		},
		{
			name: "missing fingerprint and rule ID",
			s: Suppression{
				Reason:    "Test",
				Owner:     "test@example.com",
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.s.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	err := &ValidationError{Field: "reason", Message: "is required"}
	assert.Equal(t, "reason: is required", err.Error())
}
