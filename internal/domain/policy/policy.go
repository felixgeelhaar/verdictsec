package policy

import (
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// BaselineMode defines how baselines affect decisions.
type BaselineMode string

const (
	BaselineModeStrict BaselineMode = "strict" // Baselined findings don't affect decision
	BaselineModeWarn   BaselineMode = "warn"   // Baselined findings show but don't fail
	BaselineModeOff    BaselineMode = "off"    // Baselines ignored
)

// Policy is the aggregate root for security governance.
// It defines thresholds, suppressions, and gating rules.
type Policy struct {
	Version      string        `json:"version" yaml:"version"`
	Threshold    Threshold     `json:"threshold" yaml:"threshold"`
	Suppressions []Suppression `json:"suppressions,omitempty" yaml:"suppressions,omitempty"`
	GatingRules  []GatingRule  `json:"gating_rules,omitempty" yaml:"gating_rules,omitempty"`
	BaselineMode BaselineMode  `json:"baseline_mode" yaml:"baseline_mode"`
}

// DefaultPolicy returns sensible default policy.
func DefaultPolicy() Policy {
	return Policy{
		Version:      "1",
		Threshold:    DefaultThreshold(),
		BaselineMode: BaselineModeWarn,
		Suppressions: []Suppression{},
		GatingRules:  []GatingRule{},
	}
}

// ActiveSuppressions returns non-expired suppressions.
func (p *Policy) ActiveSuppressions() []Suppression {
	var active []Suppression
	for _, s := range p.Suppressions {
		if s.IsActive() {
			active = append(active, s)
		}
	}
	return active
}

// ExpiredSuppressions returns expired suppressions.
func (p *Policy) ExpiredSuppressions() []Suppression {
	var expired []Suppression
	for _, s := range p.Suppressions {
		if s.IsExpired() {
			expired = append(expired, s)
		}
	}
	return expired
}

// IsSuppressed checks if a finding is suppressed by any active suppression.
func (p *Policy) IsSuppressed(f *finding.Finding) bool {
	for _, s := range p.ActiveSuppressions() {
		if s.Matches(f) {
			return true
		}
	}
	return false
}

// GetSuppression returns the suppression that matches a finding, if any.
func (p *Policy) GetSuppression(f *finding.Finding) *Suppression {
	for i := range p.Suppressions {
		if p.Suppressions[i].IsActive() && p.Suppressions[i].Matches(f) {
			return &p.Suppressions[i]
		}
	}
	return nil
}

// GetThresholdForMode returns the threshold for a given mode.
// Falls back to default threshold if no mode-specific rule exists.
func (p *Policy) GetThresholdForMode(mode Mode) Threshold {
	for _, rule := range p.GatingRules {
		if rule.Mode == mode {
			return rule.Threshold
		}
	}
	return p.Threshold
}

// AddSuppression adds a new suppression to the policy.
func (p *Policy) AddSuppression(s Suppression) error {
	if err := s.Validate(); err != nil {
		return err
	}
	p.Suppressions = append(p.Suppressions, s)
	return nil
}

// RemoveSuppression removes a suppression by fingerprint or rule ID.
func (p *Policy) RemoveSuppression(fingerprint, ruleID string) bool {
	for i, s := range p.Suppressions {
		if (fingerprint != "" && s.Fingerprint == fingerprint) ||
			(ruleID != "" && s.RuleID == ruleID) {
			p.Suppressions = append(p.Suppressions[:i], p.Suppressions[i+1:]...)
			return true
		}
	}
	return false
}

// CleanupExpired removes all expired suppressions and returns the count.
func (p *Policy) CleanupExpired() int {
	var active []Suppression
	expiredCount := 0
	for _, s := range p.Suppressions {
		if s.IsActive() {
			active = append(active, s)
		} else {
			expiredCount++
		}
	}
	p.Suppressions = active
	return expiredCount
}

// Validate checks if the policy configuration is valid.
func (p *Policy) Validate() error {
	if err := p.Threshold.Validate(); err != nil {
		return fmt.Errorf("threshold: %w", err)
	}

	for i, s := range p.Suppressions {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("suppression[%d]: %w", i, err)
		}
	}

	for i, g := range p.GatingRules {
		if err := g.Validate(); err != nil {
			return fmt.Errorf("gating_rule[%d]: %w", i, err)
		}
	}

	if p.BaselineMode != BaselineModeStrict &&
		p.BaselineMode != BaselineModeWarn &&
		p.BaselineMode != BaselineModeOff {
		return &ValidationError{Field: "baseline_mode", Message: "must be 'strict', 'warn', or 'off'"}
	}

	return nil
}

// SuppressionCount returns the total number of suppressions.
func (p *Policy) SuppressionCount() int {
	return len(p.Suppressions)
}

// ActiveSuppressionCount returns the number of active (non-expired) suppressions.
func (p *Policy) ActiveSuppressionCount() int {
	return len(p.ActiveSuppressions())
}
