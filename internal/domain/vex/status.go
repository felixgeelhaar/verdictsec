// Package vex provides VEX (Vulnerability Exploitability eXchange) domain models.
package vex

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Status represents the VEX status of a vulnerability.
type Status string

// VEX status values as defined in CISA VEX specification.
const (
	StatusNotAffected       Status = "not_affected"
	StatusAffected          Status = "affected"
	StatusFixed             Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// String returns the string representation.
func (s Status) String() string {
	return string(s)
}

// IsValid returns true if the status is a known value.
func (s Status) IsValid() bool {
	switch s {
	case StatusNotAffected, StatusAffected, StatusFixed, StatusUnderInvestigation:
		return true
	default:
		return false
	}
}

// ParseStatus converts a string to a Status.
func ParseStatus(s string) (Status, error) {
	normalized := Status(strings.ToLower(strings.TrimSpace(s)))
	if !normalized.IsValid() {
		return "", fmt.Errorf("invalid VEX status: %q", s)
	}
	return normalized, nil
}

// MarshalJSON implements json.Marshaler.
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Status) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseStatus(str)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// Justification represents the justification for a not_affected status.
type Justification string

// Standard VEX justifications for not_affected status.
const (
	JustificationComponentNotPresent                 Justification = "component_not_present"
	JustificationVulnerableCodeNotPresent            Justification = "vulnerable_code_not_present"
	JustificationVulnerableCodeNotInExecutePath      Justification = "vulnerable_code_not_in_execute_path"
	JustificationVulnerableCodeCannotBeControlledByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustificationInlineMitigationsAlreadyExist       Justification = "inline_mitigations_already_exist"
)

// String returns the string representation.
func (j Justification) String() string {
	return string(j)
}

// IsValid returns true if the justification is a known value.
func (j Justification) IsValid() bool {
	switch j {
	case JustificationComponentNotPresent,
		JustificationVulnerableCodeNotPresent,
		JustificationVulnerableCodeNotInExecutePath,
		JustificationVulnerableCodeCannotBeControlledByAdversary,
		JustificationInlineMitigationsAlreadyExist:
		return true
	default:
		return false
	}
}
