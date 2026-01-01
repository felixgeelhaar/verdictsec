package finding

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityUnknown, "UNKNOWN"},
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"}, // Invalid value
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.String())
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
		hasError bool
	}{
		{"CRITICAL", SeverityCritical, false},
		{"critical", SeverityCritical, false},
		{"Critical", SeverityCritical, false},
		{"HIGH", SeverityHigh, false},
		{"high", SeverityHigh, false},
		{"MEDIUM", SeverityMedium, false},
		{"LOW", SeverityLow, false},
		{"INFO", SeverityInfo, false},
		{"UNKNOWN", SeverityUnknown, false},
		{"  HIGH  ", SeverityHigh, false}, // With whitespace
		{"invalid", SeverityUnknown, true},
		{"", SeverityUnknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseSeverity(tt.input)
			if tt.hasError {
				assert.Error(t, err)
				assert.Equal(t, SeverityUnknown, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestMustParseSeverity(t *testing.T) {
	t.Run("valid severity", func(t *testing.T) {
		assert.Equal(t, SeverityHigh, MustParseSeverity("HIGH"))
	})

	t.Run("invalid severity panics", func(t *testing.T) {
		assert.Panics(t, func() {
			MustParseSeverity("invalid")
		})
	})
}

func TestSeverity_Ordering(t *testing.T) {
	tests := []struct {
		name   string
		lower  Severity
		higher Severity
	}{
		{"Unknown < Info", SeverityUnknown, SeverityInfo},
		{"Info < Low", SeverityInfo, SeverityLow},
		{"Low < Medium", SeverityLow, SeverityMedium},
		{"Medium < High", SeverityMedium, SeverityHigh},
		{"High < Critical", SeverityHigh, SeverityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, tt.higher.IsAtLeast(tt.lower), "%s should be at least %s", tt.higher, tt.lower)
			assert.True(t, tt.higher.IsHigherThan(tt.lower), "%s should be higher than %s", tt.higher, tt.lower)
			assert.False(t, tt.lower.IsAtLeast(tt.higher), "%s should not be at least %s", tt.lower, tt.higher)
			assert.False(t, tt.lower.IsHigherThan(tt.higher), "%s should not be higher than %s", tt.lower, tt.higher)
		})
	}

	t.Run("same severity", func(t *testing.T) {
		assert.True(t, SeverityHigh.IsAtLeast(SeverityHigh))
		assert.False(t, SeverityHigh.IsHigherThan(SeverityHigh))
	})
}

func TestSeverity_IsValid(t *testing.T) {
	for _, sev := range AllSeverities() {
		assert.True(t, sev.IsValid(), "%s should be valid", sev)
	}
	assert.False(t, Severity(99).IsValid())
}

func TestSeverity_JSONRoundTrip(t *testing.T) {
	type wrapper struct {
		Severity Severity `json:"severity"`
	}

	original := wrapper{Severity: SeverityHigh}

	data, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"severity":"HIGH"`)

	var decoded wrapper
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original.Severity, decoded.Severity)
}

func TestSeverity_JSONUnmarshalError(t *testing.T) {
	type wrapper struct {
		Severity Severity `json:"severity"`
	}

	var decoded wrapper
	err := json.Unmarshal([]byte(`{"severity":"INVALID"}`), &decoded)
	assert.Error(t, err)
}

func TestAllSeverities(t *testing.T) {
	severities := AllSeverities()
	assert.Len(t, severities, 6)
	assert.Equal(t, SeverityUnknown, severities[0])
	assert.Equal(t, SeverityCritical, severities[5])

	// Verify ascending order
	for i := 1; i < len(severities); i++ {
		assert.True(t, severities[i].IsHigherThan(severities[i-1]))
	}
}

func TestSeverity_YAMLRoundTrip(t *testing.T) {
	original := SeverityHigh

	data, err := original.MarshalYAML()
	require.NoError(t, err)
	assert.Equal(t, "HIGH", data)

	var decoded Severity
	err = decoded.UnmarshalYAML(func(v interface{}) error {
		*(v.(*string)) = "MEDIUM"
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, SeverityMedium, decoded)
}

func TestSeverity_UnmarshalYAMLError(t *testing.T) {
	var decoded Severity
	err := decoded.UnmarshalYAML(func(v interface{}) error {
		*(v.(*string)) = "INVALID"
		return nil
	})
	assert.Error(t, err)
}
