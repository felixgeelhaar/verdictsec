package finding

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFingerprint_Determinism(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	// Same inputs must produce same fingerprint
	fp1 := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)
	fp2 := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)

	assert.Equal(t, fp1.Value(), fp2.Value())
	assert.Equal(t, fp1.Version(), fp2.Version())
	assert.True(t, fp1.Equals(fp2))
}

func TestNewFingerprint_DifferentInputs(t *testing.T) {
	loc1 := NewLocation("src/main.go", 10, 5, 10, 20)
	loc2 := NewLocation("src/main.go", 11, 5, 11, 20) // Different line

	fp1 := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc1)
	fp2 := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc2)

	assert.NotEqual(t, fp1.Value(), fp2.Value())
}

func TestNewFingerprint_DifferentEngines(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	fp1 := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)
	fp2 := NewFingerprint(FindingTypeSAST, "semgrep", "G401", loc)

	assert.NotEqual(t, fp1.Value(), fp2.Value())
}

func TestNewFingerprint_DifferentRules(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	fp1 := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)
	fp2 := NewFingerprint(FindingTypeSAST, "gosec", "G402", loc)

	assert.NotEqual(t, fp1.Value(), fp2.Value())
}

func TestNewFingerprint_DifferentTypes(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	fp1 := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)
	fp2 := NewFingerprint(FindingTypeVuln, "gosec", "G401", loc)

	assert.NotEqual(t, fp1.Value(), fp2.Value())
}

func TestFingerprint_ValueLength(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)
	fp := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)

	// 128-bit fingerprint = 32 hex characters
	assert.Len(t, fp.Value(), 32)
}

func TestFingerprint_Short(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)
	fp := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)

	assert.Len(t, fp.Short(), 8)
	assert.Equal(t, fp.Value()[:8], fp.Short())
}

func TestFingerprint_String(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)
	fp := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)

	// String() should return the same as Value()
	assert.Equal(t, fp.Value(), fp.String())
}

func TestFingerprint_Version(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)
	fp := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)

	assert.Equal(t, FingerprintVersion, fp.Version())
	assert.True(t, fp.IsCurrentVersion())
}

func TestNewFingerprintFromString(t *testing.T) {
	fp := NewFingerprintFromString("abc123def456", "v0")

	assert.Equal(t, "abc123def456", fp.Value())
	assert.Equal(t, "v0", fp.Version())
	assert.False(t, fp.IsCurrentVersion())
}

func TestFingerprint_Equals(t *testing.T) {
	fp1 := NewFingerprintFromString("abc123", "v1")
	fp2 := NewFingerprintFromString("abc123", "v1")
	fp3 := NewFingerprintFromString("abc123", "v2") // Different version
	fp4 := NewFingerprintFromString("def456", "v1") // Different value

	assert.True(t, fp1.Equals(fp2))
	assert.False(t, fp1.Equals(fp3))
	assert.False(t, fp1.Equals(fp4))
}

func TestFingerprint_ValueEquals(t *testing.T) {
	fp1 := NewFingerprintFromString("abc123", "v1")
	fp2 := NewFingerprintFromString("abc123", "v2") // Different version

	assert.True(t, fp1.ValueEquals(fp2))
}

func TestFingerprint_IsZero(t *testing.T) {
	assert.True(t, Fingerprint{}.IsZero())
	assert.True(t, NewFingerprintFromString("", "v1").IsZero())
	assert.False(t, NewFingerprintFromString("abc123", "v1").IsZero())
}

func TestFingerprint_JSONRoundTrip(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)
	original := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc)

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Fingerprint
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.True(t, original.Equals(decoded))
}

func TestFingerprint_PathNormalizationAffectsFingerprint(t *testing.T) {
	// Different path representations should normalize to same fingerprint
	loc1 := NewLocation("src/main.go", 10, 5, 10, 20)
	loc2 := NewLocation("./src/main.go", 10, 5, 10, 20)

	fp1 := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc1)
	fp2 := NewFingerprint(FindingTypeSAST, "gosec", "G401", loc2)

	// These should be equal because path is normalized
	assert.Equal(t, fp1.Value(), fp2.Value())
}
