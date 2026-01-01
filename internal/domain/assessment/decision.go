package assessment

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Decision represents the final assessment outcome.
// It is a value object that is immutable and comparable.
type Decision int

const (
	DecisionUnknown Decision = iota
	DecisionPass
	DecisionWarn
	DecisionFail
	DecisionError
)

var decisionNames = map[Decision]string{
	DecisionUnknown: "UNKNOWN",
	DecisionPass:    "PASS",
	DecisionWarn:    "WARN",
	DecisionFail:    "FAIL",
	DecisionError:   "ERROR",
}

var decisionValues = map[string]Decision{
	"UNKNOWN": DecisionUnknown,
	"PASS":    DecisionPass,
	"WARN":    DecisionWarn,
	"FAIL":    DecisionFail,
	"ERROR":   DecisionError,
}

// String returns the string representation of the decision.
func (d Decision) String() string {
	if name, ok := decisionNames[d]; ok {
		return name
	}
	return "UNKNOWN"
}

// ParseDecision converts a string to a Decision value.
func ParseDecision(s string) (Decision, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	if dec, ok := decisionValues[upper]; ok {
		return dec, nil
	}
	return DecisionUnknown, fmt.Errorf("invalid decision: %q", s)
}

// ExitCode returns the CLI exit code for this decision.
// 0 = PASS or WARN (success)
// 1 = FAIL (policy violation)
// 2 = ERROR (tool/config failure)
func (d Decision) ExitCode() int {
	switch d {
	case DecisionPass, DecisionWarn:
		return 0
	case DecisionFail:
		return 1
	case DecisionError:
		return 2
	default:
		return 2
	}
}

// IsSuccess returns true if the decision indicates success (PASS or WARN).
func (d Decision) IsSuccess() bool {
	return d == DecisionPass || d == DecisionWarn
}

// IsFailure returns true if the decision indicates failure (FAIL or ERROR).
func (d Decision) IsFailure() bool {
	return d == DecisionFail || d == DecisionError
}

// IsValid returns true if the decision is a known value.
func (d Decision) IsValid() bool {
	_, ok := decisionNames[d]
	return ok
}

// MarshalJSON implements json.Marshaler.
func (d Decision) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseDecision(str)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// AllDecisions returns all valid decision values.
func AllDecisions() []Decision {
	return []Decision{
		DecisionUnknown,
		DecisionPass,
		DecisionWarn,
		DecisionFail,
		DecisionError,
	}
}
