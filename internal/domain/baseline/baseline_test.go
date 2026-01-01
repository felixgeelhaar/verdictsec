package baseline

import (
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func createTestFinding(ruleID string) *finding.Finding {
	loc := finding.NewLocation("main.go", 10, 1, 10, 20)
	return finding.NewFinding(finding.FindingTypeSAST, "gosec", ruleID, "Test finding", finding.SeverityHigh, loc)
}

const testReason = "Test baseline reason"

func TestNewBaseline(t *testing.T) {
	b := NewBaseline("./src")

	assert.Equal(t, "1", b.Version)
	assert.Equal(t, "./src", b.Scope.Target)
	assert.Equal(t, "v1", b.NormalizationVersion)
	assert.Equal(t, finding.FingerprintVersion, b.FingerprintVersion)
	assert.False(t, b.CreatedAt.IsZero())
	assert.False(t, b.UpdatedAt.IsZero())
	assert.Empty(t, b.Entries)
}

func TestNewBaselineWithScope(t *testing.T) {
	scope := NewScope("./src", "gosec", "govulncheck")
	b := NewBaselineWithScope(scope)

	assert.Equal(t, "./src", b.Scope.Target)
	assert.Equal(t, []string{"gosec", "govulncheck"}, b.Scope.EngineIDs)
}

func TestBaseline_Contains(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")

	assert.False(t, b.Contains(f))

	_ = b.Add(f, testReason)
	assert.True(t, b.Contains(f))
}

func TestBaseline_ContainsFingerprint(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")

	assert.False(t, b.ContainsFingerprint(f.Fingerprint().Value()))

	_ = b.Add(f, testReason)
	assert.True(t, b.ContainsFingerprint(f.Fingerprint().Value()))
}

func TestBaseline_GetEntry(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")

	assert.Nil(t, b.GetEntry(f))

	_ = b.Add(f, testReason)
	entry := b.GetEntry(f)
	assert.NotNil(t, entry)
	assert.Equal(t, f.Fingerprint().Value(), entry.Fingerprint)
	assert.Equal(t, testReason, entry.Reason)
}

func TestBaseline_Add(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")

	err := b.Add(f, testReason)
	assert.NoError(t, err)

	assert.Equal(t, 1, b.Count())
	assert.True(t, b.Contains(f))
}

func TestBaseline_Add_RequiresReason(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")

	err := b.Add(f, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason is required")
}

func TestBaseline_Add_UpdatesLastSeen(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")

	_ = b.Add(f, testReason)
	originalLastSeen := b.GetEntry(f).LastSeen

	time.Sleep(10 * time.Millisecond)
	_ = b.Add(f, testReason) // Add again

	assert.Equal(t, 1, b.Count()) // Still only one entry
	assert.True(t, b.GetEntry(f).LastSeen.After(originalLastSeen))
}

func TestBaseline_AddAll(t *testing.T) {
	b := NewBaseline("./src")
	findings := []*finding.Finding{
		createTestFinding("G401"),
		createTestFinding("G402"),
		createTestFinding("G403"),
	}

	err := b.AddAll(findings, testReason)
	assert.NoError(t, err)

	assert.Equal(t, 3, b.Count())
}

func TestBaseline_AddAll_RequiresReason(t *testing.T) {
	b := NewBaseline("./src")
	findings := []*finding.Finding{
		createTestFinding("G401"),
	}

	err := b.AddAll(findings, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason is required")
}

func TestBaseline_Remove(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")

	_ = b.Add(f, testReason)
	assert.Equal(t, 1, b.Count())

	removed := b.Remove(f.Fingerprint().Value())
	assert.True(t, removed)
	assert.Equal(t, 0, b.Count())
	assert.False(t, b.Contains(f))
}

func TestBaseline_Remove_NonExistent(t *testing.T) {
	b := NewBaseline("./src")

	removed := b.Remove("nonexistent")
	assert.False(t, removed)
}

func TestBaseline_RemoveStale(t *testing.T) {
	b := NewBaseline("./src")

	// Add some entries with different ages
	f1 := createTestFinding("G401")
	f2 := createTestFinding("G402")
	_ = b.Add(f1, testReason)
	_ = b.Add(f2, testReason)

	// Manually set one entry's LastSeen to be old
	b.Entries[0].LastSeen = time.Now().Add(-48 * time.Hour)
	b.rebuildIndex()

	removed := b.RemoveStale(24 * time.Hour)
	assert.Equal(t, 1, removed)
	assert.Equal(t, 1, b.Count())
}

func TestBaseline_RemoveStale_NoStale(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")
	_ = b.Add(f, testReason)

	removed := b.RemoveStale(24 * time.Hour)
	assert.Equal(t, 0, removed)
	assert.Equal(t, 1, b.Count())
}

func TestBaseline_Count(t *testing.T) {
	b := NewBaseline("./src")
	assert.Equal(t, 0, b.Count())

	_ = b.Add(createTestFinding("G401"), testReason)
	assert.Equal(t, 1, b.Count())

	_ = b.Add(createTestFinding("G402"), testReason)
	assert.Equal(t, 2, b.Count())
}

func TestBaseline_Fingerprints(t *testing.T) {
	b := NewBaseline("./src")
	f1 := createTestFinding("G401")
	f2 := createTestFinding("G402")

	_ = b.Add(f1, testReason)
	_ = b.Add(f2, testReason)

	fps := b.Fingerprints()
	assert.Len(t, fps, 2)
	assert.Contains(t, fps, f1.Fingerprint().Value())
	assert.Contains(t, fps, f2.Fingerprint().Value())
}

func TestBaseline_EntriesByEngine(t *testing.T) {
	b := NewBaseline("./src")

	loc := finding.NewLocation("main.go", 10, 1, 10, 20)
	f1 := finding.NewFinding(finding.FindingTypeSAST, "gosec", "G401", "Test", finding.SeverityHigh, loc)
	f2 := finding.NewFinding(finding.FindingTypeVuln, "govulncheck", "CVE-2024-1234", "Test", finding.SeverityHigh, loc)

	_ = b.Add(f1, testReason)
	_ = b.Add(f2, testReason)

	byEngine := b.EntriesByEngine()
	assert.Len(t, byEngine, 2)
	assert.Len(t, byEngine["gosec"], 1)
	assert.Len(t, byEngine["govulncheck"], 1)
}

func TestBaseline_MatchesScope(t *testing.T) {
	b := NewBaseline("./src")

	assert.True(t, b.MatchesScope("./src"))
	assert.False(t, b.MatchesScope("./other"))
}

func TestBaseline_Merge(t *testing.T) {
	b1 := NewBaseline("./src")
	b2 := NewBaseline("./src")

	f1 := createTestFinding("G401")
	f2 := createTestFinding("G402")
	f3 := createTestFinding("G403")

	_ = b1.Add(f1, testReason)
	_ = b1.Add(f2, testReason)

	_ = b2.Add(f2, testReason) // Overlap
	_ = b2.Add(f3, testReason)

	// Make b2's entry for f2 newer
	time.Sleep(10 * time.Millisecond)
	b2.Entries[0].LastSeen = time.Now().UTC()

	b1.Merge(b2)

	assert.Equal(t, 3, b1.Count())
	assert.True(t, b1.Contains(f1))
	assert.True(t, b1.Contains(f2))
	assert.True(t, b1.Contains(f3))
}

func TestBaseline_Merge_UpdatesTimestamps(t *testing.T) {
	b1 := NewBaseline("./src")
	b2 := NewBaseline("./src")

	f := createTestFinding("G401")
	_ = b1.Add(f, testReason)
	originalLastSeen := b1.GetEntry(f).LastSeen

	time.Sleep(10 * time.Millisecond)
	_ = b2.Add(f, testReason)

	b1.Merge(b2)

	assert.True(t, b1.GetEntry(f).LastSeen.After(originalLastSeen))
}

func TestBaseline_Clone(t *testing.T) {
	b := NewBaseline("./src")
	f1 := createTestFinding("G401")
	f2 := createTestFinding("G402")
	_ = b.Add(f1, testReason)
	_ = b.Add(f2, testReason)

	clone := b.Clone()

	assert.Equal(t, b.Version, clone.Version)
	assert.Equal(t, b.Scope, clone.Scope)
	assert.Equal(t, b.Count(), clone.Count())

	// Modifications to clone shouldn't affect original
	clone.Remove(f1.Fingerprint().Value())
	assert.Equal(t, 2, b.Count())
	assert.Equal(t, 1, clone.Count())
}

func TestBaseline_EnsureIndex_NilIndex(t *testing.T) {
	b := &Baseline{
		Entries: []Entry{
			{Fingerprint: "abc123"},
		},
		fingerprintIndex: nil,
	}

	// This should rebuild the index
	exists := b.ContainsFingerprint("abc123")
	assert.True(t, exists)
}

func TestBaseline_GetEntries(t *testing.T) {
	b := NewBaseline("./src")
	f1 := createTestFinding("G401")
	f2 := createTestFinding("G402")
	_ = b.Add(f1, testReason)
	_ = b.Add(f2, testReason)

	entries := b.GetEntries()
	assert.Len(t, entries, 2)

	// Modifying the returned slice should not affect the original
	entries[0].Fingerprint = "modified"
	assert.NotEqual(t, "modified", b.Entries[0].Fingerprint)
}

func TestBaseline_GetScope(t *testing.T) {
	scope := NewScope("./src", "gosec", "govulncheck")
	b := NewBaselineWithScope(scope)

	result := b.GetScope()
	assert.Equal(t, "./src", result.Target)
	assert.Equal(t, []string{"gosec", "govulncheck"}, result.EngineIDs)
}

func TestBaseline_GetVersion(t *testing.T) {
	b := NewBaseline("./src")
	assert.Equal(t, "1", b.GetVersion())
}

func TestBaseline_GetCreatedAt(t *testing.T) {
	before := time.Now().UTC()
	b := NewBaseline("./src")
	after := time.Now().UTC()

	createdAt := b.GetCreatedAt()
	assert.True(t, !createdAt.Before(before))
	assert.True(t, !createdAt.After(after))
}

func TestBaseline_GetUpdatedAt(t *testing.T) {
	b := NewBaseline("./src")
	initialUpdated := b.GetUpdatedAt()

	time.Sleep(10 * time.Millisecond)
	_ = b.Add(createTestFinding("G401"), testReason)

	updatedAt := b.GetUpdatedAt()
	assert.True(t, updatedAt.After(initialUpdated))
}

func TestBaseline_ErrReasonRequired(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")

	err := b.Add(f, "")
	assert.ErrorIs(t, err, ErrReasonRequired)

	err = b.AddAll([]*finding.Finding{f}, "")
	assert.ErrorIs(t, err, ErrReasonRequired)
}

func TestBaseline_GetEntryByFingerprint(t *testing.T) {
	b := NewBaseline("./src")
	f := createTestFinding("G401")

	// Not found initially
	entry := b.GetEntryByFingerprint("nonexistent")
	assert.Nil(t, entry)

	// Add entry
	_ = b.Add(f, testReason)

	// Now found
	entry = b.GetEntryByFingerprint(f.Fingerprint().Value())
	assert.NotNil(t, entry)
	assert.Equal(t, f.Fingerprint().Value(), entry.Fingerprint)
}

func TestBaseline_AddEntry(t *testing.T) {
	b := NewBaseline("./src")

	fingerprint := "test-fingerprint-123"
	b.AddEntry(fingerprint, "v1", "G401", "gosec", "Test reason")

	assert.Equal(t, 1, b.Count())
	assert.True(t, b.ContainsFingerprint(fingerprint))

	entry := b.GetEntryByFingerprint(fingerprint)
	assert.NotNil(t, entry)
	assert.Equal(t, fingerprint, entry.Fingerprint)
	assert.Equal(t, "v1", entry.FingerprintVersion)
	assert.Equal(t, "G401", entry.RuleID)
	assert.Equal(t, "gosec", entry.EngineID)
	assert.Equal(t, "Test reason", entry.Reason)
}

func TestBaseline_AddEntry_UpdateExisting(t *testing.T) {
	b := NewBaseline("./src")

	fingerprint := "test-fingerprint-123"
	b.AddEntry(fingerprint, "v1", "G401", "gosec", "First reason")
	originalTime := b.GetEntryByFingerprint(fingerprint).LastSeen

	time.Sleep(10 * time.Millisecond)
	b.AddEntry(fingerprint, "v1", "G401", "gosec", "Second reason")

	// Should still have only one entry
	assert.Equal(t, 1, b.Count())

	// LastSeen should be updated
	entry := b.GetEntryByFingerprint(fingerprint)
	assert.True(t, entry.LastSeen.After(originalTime))
}
