package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity represents normalized severity levels for security findings.
// It is a value object that is immutable and comparable.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityUnknown:  "UNKNOWN",
	SeverityInfo:     "INFO",
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

var severityValues = map[string]Severity{
	"UNKNOWN":  SeverityUnknown,
	"INFO":     SeverityInfo,
	"LOW":      SeverityLow,
	"MEDIUM":   SeverityMedium,
	"HIGH":     SeverityHigh,
	"CRITICAL": SeverityCritical,
}

// String returns the string representation of the severity.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "UNKNOWN"
}

// ParseSeverity converts a string to a Severity value.
// The comparison is case-insensitive.
func ParseSeverity(s string) (Severity, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	if sev, ok := severityValues[upper]; ok {
		return sev, nil
	}
	return SeverityUnknown, fmt.Errorf("invalid severity: %q", s)
}

// MustParseSeverity converts a string to a Severity value, panicking on error.
func MustParseSeverity(s string) Severity {
	sev, err := ParseSeverity(s)
	if err != nil {
		panic(err)
	}
	return sev
}

// IsAtLeast returns true if this severity is at least as severe as the other.
func (s Severity) IsAtLeast(other Severity) bool {
	return s >= other
}

// IsHigherThan returns true if this severity is strictly higher than the other.
func (s Severity) IsHigherThan(other Severity) bool {
	return s > other
}

// IsValid returns true if the severity is a known value.
func (s Severity) IsValid() bool {
	_, ok := severityNames[s]
	return ok
}

// MarshalJSON implements json.Marshaler.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (s Severity) MarshalYAML() (interface{}, error) {
	return s.String(), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *Severity) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	parsed, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// AllSeverities returns all valid severity values in ascending order.
func AllSeverities() []Severity {
	return []Severity{
		SeverityUnknown,
		SeverityInfo,
		SeverityLow,
		SeverityMedium,
		SeverityHigh,
		SeverityCritical,
	}
}
