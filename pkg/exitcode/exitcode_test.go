package exitcode

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/stretchr/testify/assert"
)

func TestFromDecision(t *testing.T) {
	tests := []struct {
		name       string
		decision   assessment.Decision
		strictMode bool
		expected   int
	}{
		{"pass returns success", assessment.DecisionPass, false, Success},
		{"pass strict returns success", assessment.DecisionPass, true, Success},
		{"warn returns success in local mode", assessment.DecisionWarn, false, Success},
		{"warn returns violation in strict mode", assessment.DecisionWarn, true, PolicyViolation},
		{"fail returns violation", assessment.DecisionFail, false, PolicyViolation},
		{"fail strict returns violation", assessment.DecisionFail, true, PolicyViolation},
		{"error returns error", assessment.DecisionError, false, Error},
		{"error strict returns error", assessment.DecisionError, true, Error},
		{"unknown returns error", assessment.DecisionUnknown, false, Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromDecision(tt.decision, tt.strictMode)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDescription(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{Success, "No policy violations detected"},
		{PolicyViolation, "Policy violation detected"},
		{Error, "Tool or configuration error"},
		{99, "Unknown exit code"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := Description(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSuccess(t *testing.T) {
	assert.True(t, IsSuccess(Success))
	assert.False(t, IsSuccess(PolicyViolation))
	assert.False(t, IsSuccess(Error))
}

func TestIsViolation(t *testing.T) {
	assert.False(t, IsViolation(Success))
	assert.True(t, IsViolation(PolicyViolation))
	assert.False(t, IsViolation(Error))
}

func TestIsError(t *testing.T) {
	assert.False(t, IsError(Success))
	assert.False(t, IsError(PolicyViolation))
	assert.True(t, IsError(Error))
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 0, Success)
	assert.Equal(t, 1, PolicyViolation)
	assert.Equal(t, 2, Error)
}
