package finding

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfidence_String(t *testing.T) {
	tests := []struct {
		confidence Confidence
		expected   string
	}{
		{ConfidenceUnknown, "UNKNOWN"},
		{ConfidenceLow, "LOW"},
		{ConfidenceMedium, "MEDIUM"},
		{ConfidenceHigh, "HIGH"},
		{Confidence(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.confidence.String())
		})
	}
}

func TestParseConfidence(t *testing.T) {
	tests := []struct {
		input    string
		expected Confidence
		hasError bool
	}{
		{"HIGH", ConfidenceHigh, false},
		{"high", ConfidenceHigh, false},
		{"MEDIUM", ConfidenceMedium, false},
		{"LOW", ConfidenceLow, false},
		{"UNKNOWN", ConfidenceUnknown, false},
		{"  HIGH  ", ConfidenceHigh, false},
		{"invalid", ConfidenceUnknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseConfidence(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestConfidence_IsAtLeast(t *testing.T) {
	assert.True(t, ConfidenceHigh.IsAtLeast(ConfidenceLow))
	assert.True(t, ConfidenceHigh.IsAtLeast(ConfidenceHigh))
	assert.False(t, ConfidenceLow.IsAtLeast(ConfidenceHigh))
}

func TestConfidence_JSONRoundTrip(t *testing.T) {
	type wrapper struct {
		Confidence Confidence `json:"confidence"`
	}

	original := wrapper{Confidence: ConfidenceHigh}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"confidence":"HIGH"`)

	var decoded wrapper
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original.Confidence, decoded.Confidence)
}

func TestMustParseConfidence(t *testing.T) {
	t.Run("valid confidence", func(t *testing.T) {
		assert.Equal(t, ConfidenceHigh, MustParseConfidence("HIGH"))
	})

	t.Run("invalid confidence panics", func(t *testing.T) {
		assert.Panics(t, func() {
			MustParseConfidence("invalid")
		})
	})
}

func TestConfidence_IsValid(t *testing.T) {
	for _, conf := range AllConfidences() {
		assert.True(t, conf.IsValid(), "%s should be valid", conf)
	}
	assert.False(t, Confidence(99).IsValid())
}

func TestAllConfidences(t *testing.T) {
	confidences := AllConfidences()
	assert.Len(t, confidences, 4)
	assert.Equal(t, ConfidenceUnknown, confidences[0])
	assert.Equal(t, ConfidenceHigh, confidences[3])
}

func TestConfidence_YAMLRoundTrip(t *testing.T) {
	type wrapper struct {
		Confidence Confidence `yaml:"confidence"`
	}

	original := wrapper{Confidence: ConfidenceHigh}

	data, err := original.Confidence.MarshalYAML()
	require.NoError(t, err)
	assert.Equal(t, "HIGH", data)

	var decoded Confidence
	err = decoded.UnmarshalYAML(func(v interface{}) error {
		*(v.(*string)) = "MEDIUM"
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, ConfidenceMedium, decoded)
}

func TestConfidence_UnmarshalYAMLError(t *testing.T) {
	var decoded Confidence
	err := decoded.UnmarshalYAML(func(v interface{}) error {
		*(v.(*string)) = "INVALID"
		return nil
	})
	assert.Error(t, err)
}
