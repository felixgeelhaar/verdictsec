package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Reachability indicates whether vulnerable code is actually reachable
// from the application's execution paths.
// It is a value object that is immutable and comparable.
type Reachability int

const (
	ReachabilityUnknown Reachability = iota
	ReachabilityNotReachable
	ReachabilityReachable
)

var reachabilityNames = map[Reachability]string{
	ReachabilityUnknown:      "UNKNOWN",
	ReachabilityNotReachable: "NOT_REACHABLE",
	ReachabilityReachable:    "REACHABLE",
}

var reachabilityValues = map[string]Reachability{
	"UNKNOWN":       ReachabilityUnknown,
	"NOT_REACHABLE": ReachabilityNotReachable,
	"REACHABLE":     ReachabilityReachable,
}

// String returns the string representation of the reachability.
func (r Reachability) String() string {
	if name, ok := reachabilityNames[r]; ok {
		return name
	}
	return "UNKNOWN"
}

// ParseReachability converts a string to a Reachability value.
// The comparison is case-insensitive.
func ParseReachability(s string) (Reachability, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	if reach, ok := reachabilityValues[upper]; ok {
		return reach, nil
	}
	return ReachabilityUnknown, fmt.Errorf("invalid reachability: %q", s)
}

// MustParseReachability converts a string to a Reachability value, panicking on error.
func MustParseReachability(s string) Reachability {
	reach, err := ParseReachability(s)
	if err != nil {
		panic(err)
	}
	return reach
}

// IsReachable returns true if the code is known to be reachable.
func (r Reachability) IsReachable() bool {
	return r == ReachabilityReachable
}

// IsNotReachable returns true if the code is known to not be reachable.
func (r Reachability) IsNotReachable() bool {
	return r == ReachabilityNotReachable
}

// IsKnown returns true if the reachability has been determined.
func (r Reachability) IsKnown() bool {
	return r != ReachabilityUnknown
}

// IsValid returns true if the reachability is a known value.
func (r Reachability) IsValid() bool {
	_, ok := reachabilityNames[r]
	return ok
}

// MarshalJSON implements json.Marshaler.
func (r Reachability) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *Reachability) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseReachability(str)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (r Reachability) MarshalYAML() (interface{}, error) {
	return r.String(), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (r *Reachability) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	parsed, err := ParseReachability(str)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// AllReachabilities returns all valid reachability values.
func AllReachabilities() []Reachability {
	return []Reachability{
		ReachabilityUnknown,
		ReachabilityNotReachable,
		ReachabilityReachable,
	}
}
