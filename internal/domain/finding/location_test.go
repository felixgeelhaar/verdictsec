package finding

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocation(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	assert.Equal(t, "src/main.go", loc.File())
	assert.Equal(t, 10, loc.Line())
	assert.Equal(t, 5, loc.Column())
	assert.Equal(t, 10, loc.EndLine())
	assert.Equal(t, 20, loc.EndColumn())
}

func TestNewLocation_PathNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"src/main.go", "src/main.go"},
		{"src\\main.go", "src/main.go"},       // Windows path
		{"./src/main.go", "src/main.go"},      // Leading ./
		{".\\src\\main.go", "src/main.go"},    // Windows with ./
		{"src/pkg/../main.go", "src/pkg/../main.go"}, // Don't resolve ..
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			loc := NewLocation(tt.input, 1, 0, 0, 0)
			assert.Equal(t, tt.expected, loc.File())
		})
	}
}

func TestNewLocationSimple(t *testing.T) {
	loc := NewLocationSimple("main.go", 42)

	assert.Equal(t, "main.go", loc.File())
	assert.Equal(t, 42, loc.Line())
	assert.Equal(t, 0, loc.Column())
	assert.Equal(t, 0, loc.EndLine())
	assert.Equal(t, 0, loc.EndColumn())
}

func TestLocation_String(t *testing.T) {
	tests := []struct {
		name     string
		location Location
		expected string
	}{
		{
			name:     "with column",
			location: NewLocation("main.go", 10, 5, 0, 0),
			expected: "main.go:10:5",
		},
		{
			name:     "line only",
			location: NewLocationSimple("main.go", 10),
			expected: "main.go:10",
		},
		{
			name:     "file only",
			location: NewLocation("main.go", 0, 0, 0, 0),
			expected: "main.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.location.String())
		})
	}
}

func TestLocation_Canonical(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 15, 10)
	assert.Equal(t, "src/main.go:10:5", loc.Canonical())
}

func TestLocation_Equals(t *testing.T) {
	loc1 := NewLocation("main.go", 10, 5, 10, 20)
	loc2 := NewLocation("main.go", 10, 5, 10, 20)
	loc3 := NewLocation("main.go", 10, 5, 11, 20) // Different end line

	assert.True(t, loc1.Equals(loc2))
	assert.False(t, loc1.Equals(loc3))
}

func TestLocation_SamePosition(t *testing.T) {
	loc1 := NewLocation("main.go", 10, 5, 10, 20)
	loc2 := NewLocation("main.go", 10, 5, 15, 25) // Different range
	loc3 := NewLocation("main.go", 10, 6, 10, 20) // Different column

	assert.True(t, loc1.SamePosition(loc2))
	assert.False(t, loc1.SamePosition(loc3))
}

func TestLocation_IsZero(t *testing.T) {
	assert.True(t, Location{}.IsZero())
	assert.True(t, NewLocation("", 0, 0, 0, 0).IsZero())
	assert.False(t, NewLocationSimple("main.go", 1).IsZero())
}

func TestLocation_HasRange(t *testing.T) {
	assert.True(t, NewLocation("main.go", 10, 5, 15, 10).HasRange())
	assert.True(t, NewLocation("main.go", 10, 5, 0, 10).HasRange())
	assert.False(t, NewLocation("main.go", 10, 5, 0, 0).HasRange())
}

func TestLocation_JSONRoundTrip(t *testing.T) {
	original := NewLocation("src/main.go", 10, 5, 15, 20)

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Location
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.True(t, original.Equals(decoded))
}
