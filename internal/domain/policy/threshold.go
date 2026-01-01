package policy

import (
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Threshold defines severity thresholds for decisions.
type Threshold struct {
	FailOn finding.Severity `json:"fail_on" yaml:"fail_on"`
	WarnOn finding.Severity `json:"warn_on" yaml:"warn_on"`
}

// DefaultThreshold returns sensible default thresholds.
func DefaultThreshold() Threshold {
	return Threshold{
		FailOn: finding.SeverityHigh,
		WarnOn: finding.SeverityMedium,
	}
}

// ShouldFail returns true if the given severity should cause a failure.
func (t Threshold) ShouldFail(severity finding.Severity) bool {
	return severity.IsAtLeast(t.FailOn)
}

// ShouldWarn returns true if the given severity should cause a warning.
func (t Threshold) ShouldWarn(severity finding.Severity) bool {
	return severity.IsAtLeast(t.WarnOn) && !t.ShouldFail(severity)
}

// Validate checks if the threshold configuration is valid.
func (t Threshold) Validate() error {
	if !t.FailOn.IsValid() {
		return &ValidationError{Field: "fail_on", Message: "invalid severity"}
	}
	if !t.WarnOn.IsValid() {
		return &ValidationError{Field: "warn_on", Message: "invalid severity"}
	}
	if t.WarnOn.IsHigherThan(t.FailOn) {
		return &ValidationError{Field: "warn_on", Message: "warn_on cannot be higher than fail_on"}
	}
	return nil
}
