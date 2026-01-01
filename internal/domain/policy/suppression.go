package policy

import (
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Suppression represents an accepted finding exception.
// Suppressions require owner, reason, and expiry for accountability.
type Suppression struct {
	Fingerprint string    `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	RuleID      string    `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	Reason      string    `json:"reason" yaml:"reason"`
	Owner       string    `json:"owner" yaml:"owner"`
	ExpiresAt   time.Time `json:"expires_at" yaml:"expires_at"`
	CreatedAt   time.Time `json:"created_at" yaml:"created_at"`
}

// NewSuppression creates a new suppression with the current timestamp.
func NewSuppression(fingerprint, ruleID, reason, owner string, expiresAt time.Time) *Suppression {
	return &Suppression{
		Fingerprint: fingerprint,
		RuleID:      ruleID,
		Reason:      reason,
		Owner:       owner,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now().UTC(),
	}
}

// IsExpired returns true if the suppression has expired.
func (s *Suppression) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsActive returns true if the suppression is not expired.
func (s *Suppression) IsActive() bool {
	return !s.IsExpired()
}

// Matches returns true if this suppression matches the given finding.
func (s *Suppression) Matches(f *finding.Finding) bool {
	if s.Fingerprint != "" && s.Fingerprint == f.Fingerprint().Value() {
		return true
	}
	if s.RuleID != "" && s.RuleID == f.RuleID() {
		return true
	}
	return false
}

// DaysUntilExpiry returns the number of days until expiry.
// Returns 0 if already expired.
func (s *Suppression) DaysUntilExpiry() int {
	if s.IsExpired() {
		return 0
	}
	duration := time.Until(s.ExpiresAt)
	return int(duration.Hours() / 24)
}

// Validate checks if the suppression has all required fields.
func (s *Suppression) Validate() error {
	if s.Reason == "" {
		return &ValidationError{Field: "reason", Message: "reason is required"}
	}
	if s.Owner == "" {
		return &ValidationError{Field: "owner", Message: "owner is required"}
	}
	if s.ExpiresAt.IsZero() {
		return &ValidationError{Field: "expires_at", Message: "expiry date is required"}
	}
	if s.Fingerprint == "" && s.RuleID == "" {
		return &ValidationError{Field: "fingerprint/rule_id", Message: "either fingerprint or rule_id is required"}
	}
	return nil
}

// ValidationError represents a validation error with field context.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Message
}
