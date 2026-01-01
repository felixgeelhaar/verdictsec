package assessment

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecision_String(t *testing.T) {
	tests := []struct {
		decision Decision
		expected string
	}{
		{DecisionUnknown, "UNKNOWN"},
		{DecisionPass, "PASS"},
		{DecisionWarn, "WARN"},
		{DecisionFail, "FAIL"},
		{DecisionError, "ERROR"},
		{Decision(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.decision.String())
		})
	}
}

func TestParseDecision(t *testing.T) {
	tests := []struct {
		input    string
		expected Decision
		hasError bool
	}{
		{"PASS", DecisionPass, false},
		{"pass", DecisionPass, false},
		{"WARN", DecisionWarn, false},
		{"FAIL", DecisionFail, false},
		{"ERROR", DecisionError, false},
		{"  PASS  ", DecisionPass, false},
		{"invalid", DecisionUnknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseDecision(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestDecision_ExitCode(t *testing.T) {
	tests := []struct {
		decision Decision
		expected int
	}{
		{DecisionPass, 0},
		{DecisionWarn, 0},
		{DecisionFail, 1},
		{DecisionError, 2},
		{DecisionUnknown, 2},
	}

	for _, tt := range tests {
		t.Run(tt.decision.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.decision.ExitCode())
		})
	}
}

func TestDecision_IsSuccess(t *testing.T) {
	assert.True(t, DecisionPass.IsSuccess())
	assert.True(t, DecisionWarn.IsSuccess())
	assert.False(t, DecisionFail.IsSuccess())
	assert.False(t, DecisionError.IsSuccess())
}

func TestDecision_IsFailure(t *testing.T) {
	assert.False(t, DecisionPass.IsFailure())
	assert.False(t, DecisionWarn.IsFailure())
	assert.True(t, DecisionFail.IsFailure())
	assert.True(t, DecisionError.IsFailure())
}

func TestDecision_IsValid(t *testing.T) {
	for _, d := range AllDecisions() {
		assert.True(t, d.IsValid())
	}
	assert.False(t, Decision(99).IsValid())
}

func TestAllDecisions(t *testing.T) {
	decisions := AllDecisions()
	assert.Len(t, decisions, 5)
}

func TestDecision_JSONRoundTrip(t *testing.T) {
	type wrapper struct {
		Decision Decision `json:"decision"`
	}

	original := wrapper{Decision: DecisionFail}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"decision":"FAIL"`)

	var decoded wrapper
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original.Decision, decoded.Decision)
}

func TestDecision_JSONUnmarshalError(t *testing.T) {
	type wrapper struct {
		Decision Decision `json:"decision"`
	}

	var decoded wrapper
	err := json.Unmarshal([]byte(`{"decision":"INVALID"}`), &decoded)
	assert.Error(t, err)
}
