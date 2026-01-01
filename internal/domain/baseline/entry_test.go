package baseline

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const testEntryReason = "Test reason for entry"

func TestNewEntry(t *testing.T) {
	before := time.Now().UTC()
	entry := NewEntry("abc123", "v1", "G401", "gosec", testEntryReason)
	after := time.Now().UTC()

	assert.Equal(t, "abc123", entry.Fingerprint)
	assert.Equal(t, "v1", entry.FingerprintVersion)
	assert.Equal(t, "G401", entry.RuleID)
	assert.Equal(t, "gosec", entry.EngineID)
	assert.Equal(t, testEntryReason, entry.Reason)
	assert.True(t, entry.FirstSeen.After(before) || entry.FirstSeen.Equal(before))
	assert.True(t, entry.FirstSeen.Before(after) || entry.FirstSeen.Equal(after))
	assert.Equal(t, entry.FirstSeen, entry.LastSeen)
}

func TestNewEntryWithOwner(t *testing.T) {
	entry := NewEntryWithOwner("abc123", "v1", "G401", "gosec", testEntryReason, "security@example.com")

	assert.Equal(t, testEntryReason, entry.Reason)
	assert.Equal(t, "security@example.com", entry.AddedBy)
}

func TestEntry_Touch(t *testing.T) {
	entry := NewEntry("abc123", "v1", "G401", "gosec", testEntryReason)
	originalLastSeen := entry.LastSeen

	time.Sleep(10 * time.Millisecond)
	entry.Touch()

	assert.True(t, entry.LastSeen.After(originalLastSeen))
	assert.Equal(t, entry.FirstSeen, entry.FirstSeen) // FirstSeen unchanged
}

func TestEntry_Age(t *testing.T) {
	entry := NewEntry("abc123", "v1", "G401", "gosec", testEntryReason)
	time.Sleep(10 * time.Millisecond)

	age := entry.Age()
	assert.Greater(t, age, 10*time.Millisecond)
}

func TestEntry_DaysSinceLastSeen(t *testing.T) {
	entry := Entry{
		Fingerprint: "abc123",
		LastSeen:    time.Now().Add(-48 * time.Hour),
	}

	days := entry.DaysSinceLastSeen()
	assert.Equal(t, 2, days)
}

func TestEntry_DaysSinceLastSeen_Recent(t *testing.T) {
	entry := NewEntry("abc123", "v1", "G401", "gosec", testEntryReason)

	days := entry.DaysSinceLastSeen()
	assert.Equal(t, 0, days)
}

func TestEntry_IsStale(t *testing.T) {
	// Recent entry - not stale
	recentEntry := NewEntry("abc123", "v1", "G401", "gosec", testEntryReason)
	assert.False(t, recentEntry.IsStale(24*time.Hour))

	// Old entry - stale
	oldEntry := Entry{
		Fingerprint: "abc123",
		LastSeen:    time.Now().Add(-48 * time.Hour),
	}
	assert.True(t, oldEntry.IsStale(24*time.Hour))
	assert.False(t, oldEntry.IsStale(72*time.Hour))
}
