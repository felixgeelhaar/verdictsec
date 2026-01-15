package vex

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatus_String(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusNotAffected, "not_affected"},
		{StatusAffected, "affected"},
		{StatusFixed, "fixed"},
		{StatusUnderInvestigation, "under_investigation"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestStatus_IsValid(t *testing.T) {
	tests := []struct {
		status   Status
		expected bool
	}{
		{StatusNotAffected, true},
		{StatusAffected, true},
		{StatusFixed, true},
		{StatusUnderInvestigation, true},
		{Status("invalid"), false},
		{Status(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.IsValid())
		})
	}
}

func TestParseStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected Status
		hasError bool
	}{
		{"not_affected", StatusNotAffected, false},
		{"NOT_AFFECTED", StatusNotAffected, false},
		{"  affected  ", StatusAffected, false},
		{"fixed", StatusFixed, false},
		{"under_investigation", StatusUnderInvestigation, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseStatus(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestStatus_JSONRoundTrip(t *testing.T) {
	type wrapper struct {
		Status Status `json:"status"`
	}

	original := wrapper{Status: StatusNotAffected}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"status":"not_affected"`)

	var decoded wrapper
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original.Status, decoded.Status)
}

func TestStatus_JSONUnmarshalError(t *testing.T) {
	type wrapper struct {
		Status Status `json:"status"`
	}

	var decoded wrapper
	err := json.Unmarshal([]byte(`{"status":"invalid"}`), &decoded)
	assert.Error(t, err)
}

func TestJustification_String(t *testing.T) {
	assert.Equal(t, "component_not_present", JustificationComponentNotPresent.String())
	assert.Equal(t, "vulnerable_code_not_present", JustificationVulnerableCodeNotPresent.String())
}

func TestJustification_IsValid(t *testing.T) {
	tests := []struct {
		justification Justification
		expected      bool
	}{
		{JustificationComponentNotPresent, true},
		{JustificationVulnerableCodeNotPresent, true},
		{JustificationVulnerableCodeNotInExecutePath, true},
		{JustificationVulnerableCodeCannotBeControlledByAdversary, true},
		{JustificationInlineMitigationsAlreadyExist, true},
		{Justification("invalid"), false},
		{Justification(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.justification), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.justification.IsValid())
		})
	}
}
