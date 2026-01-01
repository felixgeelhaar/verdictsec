package finding

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFinding(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	f := NewFinding(
		FindingTypeSAST,
		"gosec",
		"G401",
		"Use of weak cryptographic primitive",
		SeverityHigh,
		loc,
	)

	assert.NotEmpty(t, f.ID())
	assert.True(t, strings.HasPrefix(f.ID(), "finding-"))
	assert.Equal(t, FindingTypeSAST, f.Type())
	assert.Equal(t, "gosec", f.EngineID())
	assert.Equal(t, "G401", f.RuleID())
	assert.Equal(t, "Use of weak cryptographic primitive", f.Title())
	assert.Equal(t, SeverityHigh, f.NormalizedSeverity())
	assert.Equal(t, SeverityHigh, f.EffectiveSeverity())
	assert.Equal(t, ConfidenceUnknown, f.Confidence())
	assert.Equal(t, ReachabilityUnknown, f.Reachability())
	assert.True(t, f.Location().Equals(loc))
	assert.False(t, f.Fingerprint().IsZero())
	assert.NotEmpty(t, f.DetectedAt())
}

func TestNewFinding_WithOptions(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)
	detectedAt := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)

	f := NewFinding(
		FindingTypeVuln,
		"govulncheck",
		"GO-2024-1234",
		"SQL injection vulnerability",
		SeverityCritical,
		loc,
		WithDescription("Detailed description of the vulnerability"),
		WithConfidence(ConfidenceHigh),
		WithReachability(ReachabilityReachable),
		WithCWE("CWE-89"),
		WithCVE("CVE-2024-12345"),
		WithFixVersion("1.2.3"),
		WithEvidenceRefs([]string{"evidence-1", "evidence-2"}),
		WithMetadata("package", "database/sql"),
		WithDetectedAt(detectedAt),
	)

	assert.Equal(t, "Detailed description of the vulnerability", f.Description())
	assert.Equal(t, ConfidenceHigh, f.Confidence())
	assert.Equal(t, ReachabilityReachable, f.Reachability())
	assert.Equal(t, "CWE-89", f.CWEID())
	assert.Equal(t, "CVE-2024-12345", f.CVEID())
	assert.Equal(t, "1.2.3", f.FixVersion())
	assert.Equal(t, []string{"evidence-1", "evidence-2"}, f.EvidenceRefs())
	assert.Equal(t, "database/sql", f.Metadata()["package"])
	assert.Equal(t, detectedAt, f.DetectedAt())
}

func TestFinding_SetEffectiveSeverity(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	f := NewFinding(
		FindingTypeSAST,
		"gosec",
		"G401",
		"Test finding",
		SeverityHigh,
		loc,
	)

	assert.Equal(t, SeverityHigh, f.EffectiveSeverity())

	f.SetEffectiveSeverity(SeverityMedium)
	assert.Equal(t, SeverityMedium, f.EffectiveSeverity())
	// Normalized severity remains unchanged
	assert.Equal(t, SeverityHigh, f.NormalizedSeverity())
}

func TestFinding_Predicates(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	t.Run("HasCVE", func(t *testing.T) {
		f := NewFinding(FindingTypeVuln, "govulncheck", "GO-1", "Test", SeverityHigh, loc)
		assert.False(t, f.HasCVE())

		f = NewFinding(FindingTypeVuln, "govulncheck", "GO-1", "Test", SeverityHigh, loc,
			WithCVE("CVE-2024-1234"))
		assert.True(t, f.HasCVE())
	})

	t.Run("HasCWE", func(t *testing.T) {
		f := NewFinding(FindingTypeSAST, "gosec", "G401", "Test", SeverityHigh, loc)
		assert.False(t, f.HasCWE())

		f = NewFinding(FindingTypeSAST, "gosec", "G401", "Test", SeverityHigh, loc,
			WithCWE("CWE-327"))
		assert.True(t, f.HasCWE())
	})

	t.Run("HasFix", func(t *testing.T) {
		f := NewFinding(FindingTypeVuln, "govulncheck", "GO-1", "Test", SeverityHigh, loc)
		assert.False(t, f.HasFix())

		f = NewFinding(FindingTypeVuln, "govulncheck", "GO-1", "Test", SeverityHigh, loc,
			WithFixVersion("1.2.3"))
		assert.True(t, f.HasFix())
	})

	t.Run("IsReachable", func(t *testing.T) {
		f := NewFinding(FindingTypeVuln, "govulncheck", "GO-1", "Test", SeverityHigh, loc)
		assert.False(t, f.IsReachable())

		f = NewFinding(FindingTypeVuln, "govulncheck", "GO-1", "Test", SeverityHigh, loc,
			WithReachability(ReachabilityReachable))
		assert.True(t, f.IsReachable())

		f = NewFinding(FindingTypeVuln, "govulncheck", "GO-1", "Test", SeverityHigh, loc,
			WithReachability(ReachabilityNotReachable))
		assert.False(t, f.IsReachable())
	})
}

func TestFinding_SameAs(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	f1 := NewFinding(FindingTypeSAST, "gosec", "G401", "Finding 1", SeverityHigh, loc)
	f2 := NewFinding(FindingTypeSAST, "gosec", "G401", "Finding 2", SeverityMedium, loc)
	f3 := NewFinding(FindingTypeSAST, "gosec", "G402", "Finding 3", SeverityHigh, loc) // Different rule

	// Same fingerprint despite different titles and severities
	assert.True(t, f1.SameAs(f2))
	assert.True(t, f2.SameAs(f1))

	// Different rule = different finding
	assert.False(t, f1.SameAs(f3))

	// Nil check
	assert.False(t, f1.SameAs(nil))
}

func TestFinding_UniqueIDs(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	f1 := NewFinding(FindingTypeSAST, "gosec", "G401", "Test", SeverityHigh, loc)
	f2 := NewFinding(FindingTypeSAST, "gosec", "G401", "Test", SeverityHigh, loc)

	// IDs should be unique even for identical findings
	assert.NotEqual(t, f1.ID(), f2.ID())

	// But fingerprints should be the same
	assert.True(t, f1.Fingerprint().Equals(f2.Fingerprint()))
}

func TestFinding_JSONRoundTrip(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)
	detectedAt := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)

	original := NewFinding(
		FindingTypeSAST,
		"gosec",
		"G401",
		"Use of weak cryptographic primitive",
		SeverityHigh,
		loc,
		WithDescription("Blacklisted import crypto/md5"),
		WithConfidence(ConfidenceHigh),
		WithReachability(ReachabilityReachable),
		WithCWE("CWE-327"),
		WithMetadata("package", "crypto/md5"),
		WithDetectedAt(detectedAt),
	)

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Finding
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ID(), decoded.ID())
	assert.Equal(t, original.Type(), decoded.Type())
	assert.Equal(t, original.EngineID(), decoded.EngineID())
	assert.Equal(t, original.RuleID(), decoded.RuleID())
	assert.Equal(t, original.Title(), decoded.Title())
	assert.Equal(t, original.Description(), decoded.Description())
	assert.Equal(t, original.NormalizedSeverity(), decoded.NormalizedSeverity())
	assert.Equal(t, original.EffectiveSeverity(), decoded.EffectiveSeverity())
	assert.Equal(t, original.Confidence(), decoded.Confidence())
	assert.Equal(t, original.Reachability(), decoded.Reachability())
	assert.True(t, original.Location().Equals(decoded.Location()))
	assert.True(t, original.Fingerprint().Equals(decoded.Fingerprint()))
	assert.Equal(t, original.CWEID(), decoded.CWEID())
	assert.Equal(t, original.Metadata()["package"], decoded.Metadata()["package"])
	assert.Equal(t, original.DetectedAt().Unix(), decoded.DetectedAt().Unix())
}

func TestFinding_JSONContainsExpectedFields(t *testing.T) {
	loc := NewLocation("src/main.go", 10, 5, 10, 20)

	f := NewFinding(
		FindingTypeSAST,
		"gosec",
		"G401",
		"Test finding",
		SeverityHigh,
		loc,
		WithCWE("CWE-327"),
	)

	data, err := json.Marshal(f)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"type":"sast"`)
	assert.Contains(t, jsonStr, `"engine_id":"gosec"`)
	assert.Contains(t, jsonStr, `"rule_id":"G401"`)
	assert.Contains(t, jsonStr, `"normalized_severity":"HIGH"`)
	assert.Contains(t, jsonStr, `"cwe_id":"CWE-327"`)
}
