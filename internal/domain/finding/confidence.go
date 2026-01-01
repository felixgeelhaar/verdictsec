package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Confidence represents the detection confidence level for a finding.
// It is a value object that is immutable and comparable.
type Confidence int

const (
	ConfidenceUnknown Confidence = iota
	ConfidenceLow
	ConfidenceMedium
	ConfidenceHigh
)

var confidenceNames = map[Confidence]string{
	ConfidenceUnknown: "UNKNOWN",
	ConfidenceLow:     "LOW",
	ConfidenceMedium:  "MEDIUM",
	ConfidenceHigh:    "HIGH",
}

var confidenceValues = map[string]Confidence{
	"UNKNOWN": ConfidenceUnknown,
	"LOW":     ConfidenceLow,
	"MEDIUM":  ConfidenceMedium,
	"HIGH":    ConfidenceHigh,
}

// String returns the string representation of the confidence.
func (c Confidence) String() string {
	if name, ok := confidenceNames[c]; ok {
		return name
	}
	return "UNKNOWN"
}

// ParseConfidence converts a string to a Confidence value.
// The comparison is case-insensitive.
func ParseConfidence(s string) (Confidence, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	if conf, ok := confidenceValues[upper]; ok {
		return conf, nil
	}
	return ConfidenceUnknown, fmt.Errorf("invalid confidence: %q", s)
}

// MustParseConfidence converts a string to a Confidence value, panicking on error.
func MustParseConfidence(s string) Confidence {
	conf, err := ParseConfidence(s)
	if err != nil {
		panic(err)
	}
	return conf
}

// IsAtLeast returns true if this confidence is at least as high as the other.
func (c Confidence) IsAtLeast(other Confidence) bool {
	return c >= other
}

// IsValid returns true if the confidence is a known value.
func (c Confidence) IsValid() bool {
	_, ok := confidenceNames[c]
	return ok
}

// MarshalJSON implements json.Marshaler.
func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *Confidence) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseConfidence(str)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (c Confidence) MarshalYAML() (interface{}, error) {
	return c.String(), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *Confidence) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	parsed, err := ParseConfidence(str)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// AllConfidences returns all valid confidence values in ascending order.
func AllConfidences() []Confidence {
	return []Confidence{
		ConfidenceUnknown,
		ConfidenceLow,
		ConfidenceMedium,
		ConfidenceHigh,
	}
}
