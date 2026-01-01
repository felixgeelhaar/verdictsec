package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FindingType categorizes the type of security finding.
// It is a value object that is immutable and comparable.
type FindingType int

const (
	FindingTypeUnknown FindingType = iota
	FindingTypeSAST
	FindingTypeVuln
	FindingTypeSecret
	FindingTypeSBOM
)

var findingTypeNames = map[FindingType]string{
	FindingTypeUnknown: "unknown",
	FindingTypeSAST:    "sast",
	FindingTypeVuln:    "vuln",
	FindingTypeSecret:  "secret",
	FindingTypeSBOM:    "sbom",
}

var findingTypeValues = map[string]FindingType{
	"unknown": FindingTypeUnknown,
	"sast":    FindingTypeSAST,
	"vuln":    FindingTypeVuln,
	"secret":  FindingTypeSecret,
	"sbom":    FindingTypeSBOM,
}

// String returns the string representation of the finding type.
func (t FindingType) String() string {
	if name, ok := findingTypeNames[t]; ok {
		return name
	}
	return "unknown"
}

// ParseFindingType converts a string to a FindingType value.
// The comparison is case-insensitive.
func ParseFindingType(s string) (FindingType, error) {
	lower := strings.ToLower(strings.TrimSpace(s))
	if ft, ok := findingTypeValues[lower]; ok {
		return ft, nil
	}
	return FindingTypeUnknown, fmt.Errorf("invalid finding type: %q", s)
}

// MustParseFindingType converts a string to a FindingType value, panicking on error.
func MustParseFindingType(s string) FindingType {
	ft, err := ParseFindingType(s)
	if err != nil {
		panic(err)
	}
	return ft
}

// IsValid returns true if the finding type is a known value.
func (t FindingType) IsValid() bool {
	_, ok := findingTypeNames[t]
	return ok
}

// MarshalJSON implements json.Marshaler.
func (t FindingType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *FindingType) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := ParseFindingType(str)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

// AllFindingTypes returns all valid finding types.
func AllFindingTypes() []FindingType {
	return []FindingType{
		FindingTypeUnknown,
		FindingTypeSAST,
		FindingTypeVuln,
		FindingTypeSecret,
		FindingTypeSBOM,
	}
}
