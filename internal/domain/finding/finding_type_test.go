package finding

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindingType_String(t *testing.T) {
	tests := []struct {
		findingType FindingType
		expected    string
	}{
		{FindingTypeUnknown, "unknown"},
		{FindingTypeSAST, "sast"},
		{FindingTypeVuln, "vuln"},
		{FindingTypeSecret, "secret"},
		{FindingTypeSBOM, "sbom"},
		{FindingType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.findingType.String())
		})
	}
}

func TestParseFindingType(t *testing.T) {
	tests := []struct {
		input    string
		expected FindingType
		hasError bool
	}{
		{"sast", FindingTypeSAST, false},
		{"SAST", FindingTypeSAST, false},
		{"vuln", FindingTypeVuln, false},
		{"secret", FindingTypeSecret, false},
		{"sbom", FindingTypeSBOM, false},
		{"unknown", FindingTypeUnknown, false},
		{"  sast  ", FindingTypeSAST, false},
		{"invalid", FindingTypeUnknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseFindingType(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestMustParseFindingType(t *testing.T) {
	t.Run("valid type", func(t *testing.T) {
		assert.Equal(t, FindingTypeSAST, MustParseFindingType("sast"))
	})

	t.Run("invalid type panics", func(t *testing.T) {
		assert.Panics(t, func() {
			MustParseFindingType("invalid")
		})
	})
}

func TestFindingType_IsValid(t *testing.T) {
	for _, ft := range AllFindingTypes() {
		assert.True(t, ft.IsValid(), "%s should be valid", ft)
	}
	assert.False(t, FindingType(99).IsValid())
}

func TestAllFindingTypes(t *testing.T) {
	types := AllFindingTypes()
	assert.Len(t, types, 5)
	assert.Equal(t, FindingTypeUnknown, types[0])
	assert.Equal(t, FindingTypeSBOM, types[4])
}

func TestFindingType_JSONRoundTrip(t *testing.T) {
	type wrapper struct {
		Type FindingType `json:"type"`
	}

	original := wrapper{Type: FindingTypeSAST}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"type":"sast"`)

	var decoded wrapper
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original.Type, decoded.Type)
}

func TestFindingType_JSONUnmarshalError(t *testing.T) {
	type wrapper struct {
		Type FindingType `json:"type"`
	}

	var decoded wrapper
	err := json.Unmarshal([]byte(`{"type":"invalid"}`), &decoded)
	assert.Error(t, err)
}
