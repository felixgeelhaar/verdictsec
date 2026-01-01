package finding

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReachability_String(t *testing.T) {
	tests := []struct {
		reachability Reachability
		expected     string
	}{
		{ReachabilityUnknown, "UNKNOWN"},
		{ReachabilityNotReachable, "NOT_REACHABLE"},
		{ReachabilityReachable, "REACHABLE"},
		{Reachability(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.reachability.String())
		})
	}
}

func TestParseReachability(t *testing.T) {
	tests := []struct {
		input    string
		expected Reachability
		hasError bool
	}{
		{"REACHABLE", ReachabilityReachable, false},
		{"reachable", ReachabilityReachable, false},
		{"NOT_REACHABLE", ReachabilityNotReachable, false},
		{"UNKNOWN", ReachabilityUnknown, false},
		{"invalid", ReachabilityUnknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseReachability(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestReachability_Predicates(t *testing.T) {
	assert.True(t, ReachabilityReachable.IsReachable())
	assert.False(t, ReachabilityNotReachable.IsReachable())
	assert.False(t, ReachabilityUnknown.IsReachable())

	assert.True(t, ReachabilityNotReachable.IsNotReachable())
	assert.False(t, ReachabilityReachable.IsNotReachable())

	assert.True(t, ReachabilityReachable.IsKnown())
	assert.True(t, ReachabilityNotReachable.IsKnown())
	assert.False(t, ReachabilityUnknown.IsKnown())
}

func TestReachability_JSONRoundTrip(t *testing.T) {
	type wrapper struct {
		Reachability Reachability `json:"reachability"`
	}

	original := wrapper{Reachability: ReachabilityReachable}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"reachability":"REACHABLE"`)

	var decoded wrapper
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original.Reachability, decoded.Reachability)
}

func TestMustParseReachability(t *testing.T) {
	t.Run("valid reachability", func(t *testing.T) {
		assert.Equal(t, ReachabilityReachable, MustParseReachability("REACHABLE"))
	})

	t.Run("invalid reachability panics", func(t *testing.T) {
		assert.Panics(t, func() {
			MustParseReachability("invalid")
		})
	})
}

func TestReachability_IsValid(t *testing.T) {
	for _, reach := range AllReachabilities() {
		assert.True(t, reach.IsValid(), "%s should be valid", reach)
	}
	assert.False(t, Reachability(99).IsValid())
}

func TestAllReachabilities(t *testing.T) {
	reachabilities := AllReachabilities()
	assert.Len(t, reachabilities, 3)
	assert.Equal(t, ReachabilityUnknown, reachabilities[0])
	assert.Equal(t, ReachabilityReachable, reachabilities[2])
}

func TestReachability_YAMLRoundTrip(t *testing.T) {
	original := ReachabilityReachable

	data, err := original.MarshalYAML()
	require.NoError(t, err)
	assert.Equal(t, "REACHABLE", data)

	var decoded Reachability
	err = decoded.UnmarshalYAML(func(v interface{}) error {
		*(v.(*string)) = "NOT_REACHABLE"
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, ReachabilityNotReachable, decoded)
}

func TestReachability_UnmarshalYAMLError(t *testing.T) {
	var decoded Reachability
	err := decoded.UnmarshalYAML(func(v interface{}) error {
		*(v.(*string)) = "INVALID"
		return nil
	})
	assert.Error(t, err)
}
