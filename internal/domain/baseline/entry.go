package baseline

import (
	"time"
)

// Entry represents a single baselined finding.
type Entry struct {
	Fingerprint        string    `json:"fingerprint"`
	FingerprintVersion string    `json:"fingerprint_version"`
	RuleID             string    `json:"rule_id"`
	EngineID           string    `json:"engine_id"`
	Reason             string    `json:"reason"`
	AddedBy            string    `json:"added_by,omitempty"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
}

// NewEntry creates a new baseline entry with a required reason.
func NewEntry(fingerprint, fingerprintVersion, ruleID, engineID, reason string) Entry {
	now := time.Now().UTC()
	return Entry{
		Fingerprint:        fingerprint,
		FingerprintVersion: fingerprintVersion,
		RuleID:             ruleID,
		EngineID:           engineID,
		Reason:             reason,
		FirstSeen:          now,
		LastSeen:           now,
	}
}

// NewEntryWithOwner creates a new baseline entry with reason and owner.
func NewEntryWithOwner(fingerprint, fingerprintVersion, ruleID, engineID, reason, addedBy string) Entry {
	entry := NewEntry(fingerprint, fingerprintVersion, ruleID, engineID, reason)
	entry.AddedBy = addedBy
	return entry
}

// Touch updates the LastSeen timestamp.
func (e *Entry) Touch() {
	e.LastSeen = time.Now().UTC()
}

// Age returns the duration since the entry was first seen.
func (e Entry) Age() time.Duration {
	return time.Since(e.FirstSeen)
}

// DaysSinceLastSeen returns the number of days since last seen.
func (e Entry) DaysSinceLastSeen() int {
	return int(time.Since(e.LastSeen).Hours() / 24)
}

// IsStale returns true if the entry hasn't been seen for the given duration.
func (e Entry) IsStale(threshold time.Duration) bool {
	return time.Since(e.LastSeen) > threshold
}
