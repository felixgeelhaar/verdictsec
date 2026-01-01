package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// FingerprintVersion tracks the fingerprinting algorithm version.
// This must be incremented if the fingerprinting algorithm changes.
const FingerprintVersion = "v1"

// Fingerprint is a stable, deterministic identifier for a finding.
// It is a value object that is immutable and comparable.
// The fingerprint is generated from finding type, engine ID, rule ID, and location.
// It never uses timestamps, absolute paths, or other non-deterministic data.
type Fingerprint struct {
	value   string
	version string
}

// NewFingerprint creates a fingerprint from finding components.
// The fingerprint is a SHA-256 hash (truncated to 128 bits) of the canonical representation.
func NewFingerprint(findingType FindingType, engineID, ruleID string, location Location) Fingerprint {
	// Canonical representation for hashing
	// Format: version|type|engine|rule|location
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s",
		FingerprintVersion,
		findingType.String(),
		engineID,
		ruleID,
		location.Canonical(),
	)

	hash := sha256.Sum256([]byte(canonical))
	return Fingerprint{
		value:   hex.EncodeToString(hash[:16]), // 128-bit fingerprint (32 hex chars)
		version: FingerprintVersion,
	}
}

// NewFingerprintFromString creates a fingerprint from an existing value.
// This is used when loading fingerprints from storage.
func NewFingerprintFromString(value, version string) Fingerprint {
	return Fingerprint{
		value:   value,
		version: version,
	}
}

// Value returns the fingerprint hash value.
func (f Fingerprint) Value() string { return f.value }

// Version returns the fingerprinting algorithm version.
func (f Fingerprint) Version() string { return f.version }

// String returns the fingerprint value (same as Value).
func (f Fingerprint) String() string { return f.value }

// Short returns the first 8 characters of the fingerprint for display.
func (f Fingerprint) Short() string {
	if len(f.value) >= 8 {
		return f.value[:8]
	}
	return f.value
}

// Equals compares two fingerprints for equality.
// Both value and version must match.
func (f Fingerprint) Equals(other Fingerprint) bool {
	return f.value == other.value && f.version == other.version
}

// ValueEquals compares only the fingerprint values, ignoring version.
func (f Fingerprint) ValueEquals(other Fingerprint) bool {
	return f.value == other.value
}

// IsZero returns true if the fingerprint is empty.
func (f Fingerprint) IsZero() bool {
	return f.value == ""
}

// IsCurrentVersion returns true if the fingerprint was generated with the current algorithm version.
func (f Fingerprint) IsCurrentVersion() bool {
	return f.version == FingerprintVersion
}

// fingerprintJSON is used for JSON marshaling/unmarshaling.
type fingerprintJSON struct {
	Value   string `json:"value"`
	Version string `json:"version"`
}

// MarshalJSON implements json.Marshaler.
func (f Fingerprint) MarshalJSON() ([]byte, error) {
	return json.Marshal(fingerprintJSON{
		Value:   f.value,
		Version: f.version,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (f *Fingerprint) UnmarshalJSON(data []byte) error {
	var fj fingerprintJSON
	if err := json.Unmarshal(data, &fj); err != nil {
		return err
	}
	*f = NewFingerprintFromString(fj.Value, fj.Version)
	return nil
}
