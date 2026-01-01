package baseline

import (
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Baseline is the aggregate root for existing (accepted) findings.
// It tracks findings by fingerprint to distinguish new from existing issues.
type Baseline struct {
	Version              string           `json:"version"`
	Scope                Scope            `json:"scope"`
	NormalizationVersion string           `json:"normalization_version"`
	FingerprintVersion   string           `json:"fingerprint_version"`
	CreatedAt            time.Time        `json:"created_at"`
	UpdatedAt            time.Time        `json:"updated_at"`
	Entries              []Entry          `json:"entries"`
	fingerprintIndex     map[string]*Entry // Internal index for fast lookup
}

// NewBaseline creates a new baseline for a target.
func NewBaseline(target string) *Baseline {
	return &Baseline{
		Version: "1",
		Scope: Scope{
			Target: target,
		},
		NormalizationVersion: "v1",
		FingerprintVersion:   finding.FingerprintVersion,
		CreatedAt:            time.Now().UTC(),
		UpdatedAt:            time.Now().UTC(),
		Entries:              []Entry{},
		fingerprintIndex:     make(map[string]*Entry),
	}
}

// NewBaselineWithScope creates a new baseline with a specific scope.
func NewBaselineWithScope(scope Scope) *Baseline {
	return &Baseline{
		Version:              "1",
		Scope:                scope,
		NormalizationVersion: "v1",
		FingerprintVersion:   finding.FingerprintVersion,
		CreatedAt:            time.Now().UTC(),
		UpdatedAt:            time.Now().UTC(),
		Entries:              []Entry{},
		fingerprintIndex:     make(map[string]*Entry),
	}
}

// Contains checks if a finding is in the baseline.
func (b *Baseline) Contains(f *finding.Finding) bool {
	b.ensureIndex()
	_, exists := b.fingerprintIndex[f.Fingerprint().Value()]
	return exists
}

// ContainsFingerprint checks if a fingerprint is in the baseline.
func (b *Baseline) ContainsFingerprint(fingerprint string) bool {
	b.ensureIndex()
	_, exists := b.fingerprintIndex[fingerprint]
	return exists
}

// GetEntry returns the entry for a finding, if it exists.
func (b *Baseline) GetEntry(f *finding.Finding) *Entry {
	b.ensureIndex()
	return b.fingerprintIndex[f.Fingerprint().Value()]
}

// GetEntryByFingerprint returns the entry for a fingerprint string, if it exists.
func (b *Baseline) GetEntryByFingerprint(fingerprint string) *Entry {
	b.ensureIndex()
	return b.fingerprintIndex[fingerprint]
}

// Add adds a finding to the baseline with a reason.
// If the finding already exists, its LastSeen is updated.
// Returns ErrReasonRequired if reason is empty.
func (b *Baseline) Add(f *finding.Finding, reason string) error {
	if reason == "" {
		return ErrReasonRequired
	}

	b.ensureIndex()
	fp := f.Fingerprint().Value()

	if entry, exists := b.fingerprintIndex[fp]; exists {
		entry.Touch()
	} else {
		entry := NewEntry(fp, f.Fingerprint().Version(), f.RuleID(), f.EngineID(), reason)
		b.Entries = append(b.Entries, entry)
		b.fingerprintIndex[fp] = &b.Entries[len(b.Entries)-1]
	}
	b.UpdatedAt = time.Now().UTC()
	return nil
}

// AddAll adds multiple findings to the baseline with a shared reason.
// Returns ErrReasonRequired if reason is empty.
func (b *Baseline) AddAll(findings []*finding.Finding, reason string) error {
	if reason == "" {
		return ErrReasonRequired
	}
	for _, f := range findings {
		if err := b.Add(f, reason); err != nil {
			return err
		}
	}
	return nil
}

// AddEntry adds an entry directly to the baseline using a known fingerprint.
// This is used when loading from a stored baseline file.
func (b *Baseline) AddEntry(fingerprint, fingerprintVersion, ruleID, engineID, reason string) {
	b.ensureIndex()

	if _, exists := b.fingerprintIndex[fingerprint]; exists {
		// Entry already exists, update LastSeen
		b.fingerprintIndex[fingerprint].Touch()
	} else {
		entry := NewEntry(fingerprint, fingerprintVersion, ruleID, engineID, reason)
		b.Entries = append(b.Entries, entry)
		b.fingerprintIndex[fingerprint] = &b.Entries[len(b.Entries)-1]
	}
	b.UpdatedAt = time.Now().UTC()
}

// Remove removes a finding from the baseline by fingerprint.
func (b *Baseline) Remove(fingerprint string) bool {
	b.ensureIndex()
	if _, exists := b.fingerprintIndex[fingerprint]; !exists {
		return false
	}

	delete(b.fingerprintIndex, fingerprint)

	// Rebuild entries slice
	newEntries := make([]Entry, 0, len(b.Entries)-1)
	for _, e := range b.Entries {
		if e.Fingerprint != fingerprint {
			newEntries = append(newEntries, e)
		}
	}
	b.Entries = newEntries
	b.UpdatedAt = time.Now().UTC()

	// Rebuild index
	b.rebuildIndex()
	return true
}

// RemoveStale removes entries that haven't been seen for the given duration.
// Returns the number of entries removed.
func (b *Baseline) RemoveStale(threshold time.Duration) int {
	var active []Entry
	removedCount := 0

	for _, e := range b.Entries {
		if e.IsStale(threshold) {
			removedCount++
		} else {
			active = append(active, e)
		}
	}

	if removedCount > 0 {
		b.Entries = active
		b.rebuildIndex()
		b.UpdatedAt = time.Now().UTC()
	}

	return removedCount
}

// Count returns the number of entries in the baseline.
func (b *Baseline) Count() int {
	return len(b.Entries)
}

// Fingerprints returns all fingerprints in the baseline.
func (b *Baseline) Fingerprints() []string {
	fps := make([]string, len(b.Entries))
	for i, e := range b.Entries {
		fps[i] = e.Fingerprint
	}
	return fps
}

// EntriesByEngine returns entries grouped by engine ID.
func (b *Baseline) EntriesByEngine() map[string][]Entry {
	result := make(map[string][]Entry)
	for _, e := range b.Entries {
		result[e.EngineID] = append(result[e.EngineID], e)
	}
	return result
}

// GetEntries returns a defensive copy of all entries.
func (b *Baseline) GetEntries() []Entry {
	result := make([]Entry, len(b.Entries))
	copy(result, b.Entries)
	return result
}

// GetScope returns the baseline scope.
func (b *Baseline) GetScope() Scope {
	return b.Scope
}

// GetVersion returns the baseline version.
func (b *Baseline) GetVersion() string {
	return b.Version
}

// GetCreatedAt returns when the baseline was created.
func (b *Baseline) GetCreatedAt() time.Time {
	return b.CreatedAt
}

// GetUpdatedAt returns when the baseline was last updated.
func (b *Baseline) GetUpdatedAt() time.Time {
	return b.UpdatedAt
}

// MatchesScope returns true if the baseline scope matches the given target.
func (b *Baseline) MatchesScope(target string) bool {
	return b.Scope.MatchesTarget(target)
}

// ensureIndex builds the fingerprint index if not already built.
func (b *Baseline) ensureIndex() {
	if b.fingerprintIndex == nil {
		b.rebuildIndex()
	}
}

// rebuildIndex rebuilds the fingerprint index from entries.
func (b *Baseline) rebuildIndex() {
	b.fingerprintIndex = make(map[string]*Entry, len(b.Entries))
	for i := range b.Entries {
		b.fingerprintIndex[b.Entries[i].Fingerprint] = &b.Entries[i]
	}
}

// Merge combines another baseline into this one.
// Entries from the other baseline are added or updated.
func (b *Baseline) Merge(other *Baseline) {
	b.ensureIndex()
	for _, entry := range other.Entries {
		if existing, exists := b.fingerprintIndex[entry.Fingerprint]; exists {
			// Update LastSeen if newer
			if entry.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = entry.LastSeen
			}
			// Keep earlier FirstSeen
			if entry.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = entry.FirstSeen
			}
		} else {
			b.Entries = append(b.Entries, entry)
			b.fingerprintIndex[entry.Fingerprint] = &b.Entries[len(b.Entries)-1]
		}
	}
	b.UpdatedAt = time.Now().UTC()
}

// Clone creates a deep copy of the baseline.
func (b *Baseline) Clone() *Baseline {
	clone := &Baseline{
		Version:              b.Version,
		Scope:                b.Scope,
		NormalizationVersion: b.NormalizationVersion,
		FingerprintVersion:   b.FingerprintVersion,
		CreatedAt:            b.CreatedAt,
		UpdatedAt:            b.UpdatedAt,
		Entries:              make([]Entry, len(b.Entries)),
	}
	copy(clone.Entries, b.Entries)
	clone.rebuildIndex()
	return clone
}
