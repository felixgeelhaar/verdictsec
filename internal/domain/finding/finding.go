package finding

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Finding represents a normalized security finding.
// It is an entity with a unique ID and stable fingerprint.
// Finding is immutable after creation, except for effective severity
// which can be adjusted by policy evaluation.
type Finding struct {
	id                 string
	findingType        FindingType
	engineID           string
	ruleID             string
	title              string
	description        string
	normalizedSeverity Severity
	effectiveSeverity  Severity
	confidence         Confidence
	reachability       Reachability
	location           Location
	fingerprint        Fingerprint
	cweID              string
	cveID              string
	fixVersion         string
	evidenceRefs       []string
	metadata           map[string]any
	detectedAt         time.Time
}

// FindingOption is a functional option for creating findings.
type FindingOption func(*Finding)

// NewFinding creates a new finding with required fields.
// The fingerprint is automatically generated from the finding type, engine ID, rule ID, and location.
func NewFinding(
	findingType FindingType,
	engineID string,
	ruleID string,
	title string,
	severity Severity,
	location Location,
	opts ...FindingOption,
) *Finding {
	f := &Finding{
		id:                 generateID(),
		findingType:        findingType,
		engineID:           engineID,
		ruleID:             ruleID,
		title:              title,
		normalizedSeverity: severity,
		effectiveSeverity:  severity,
		confidence:         ConfidenceUnknown,
		reachability:       ReachabilityUnknown,
		location:           location,
		metadata:           make(map[string]any),
		detectedAt:         time.Now().UTC(),
	}

	// Generate fingerprint from stable components
	f.fingerprint = NewFingerprint(findingType, engineID, ruleID, location)

	// Apply options
	for _, opt := range opts {
		opt(f)
	}

	return f
}

// Functional options for finding creation

// WithDescription sets the finding description.
func WithDescription(desc string) FindingOption {
	return func(f *Finding) { f.description = desc }
}

// WithConfidence sets the detection confidence.
func WithConfidence(c Confidence) FindingOption {
	return func(f *Finding) { f.confidence = c }
}

// WithReachability sets the reachability status.
func WithReachability(r Reachability) FindingOption {
	return func(f *Finding) { f.reachability = r }
}

// WithCWE sets the CWE identifier.
func WithCWE(cweID string) FindingOption {
	return func(f *Finding) { f.cweID = cweID }
}

// WithCVE sets the CVE identifier.
func WithCVE(cveID string) FindingOption {
	return func(f *Finding) { f.cveID = cveID }
}

// WithFixVersion sets the version that fixes the vulnerability.
func WithFixVersion(version string) FindingOption {
	return func(f *Finding) { f.fixVersion = version }
}

// WithEvidenceRefs sets the evidence references.
func WithEvidenceRefs(refs []string) FindingOption {
	return func(f *Finding) { f.evidenceRefs = refs }
}

// WithMetadata adds a metadata key-value pair.
func WithMetadata(key string, value any) FindingOption {
	return func(f *Finding) { f.metadata[key] = value }
}

// WithDetectedAt sets a specific detection time (useful for testing).
func WithDetectedAt(t time.Time) FindingOption {
	return func(f *Finding) { f.detectedAt = t.UTC() }
}

// Getters - provide immutable access to finding fields

// ID returns the unique identifier for this finding.
func (f *Finding) ID() string { return f.id }

// Type returns the finding type.
func (f *Finding) Type() FindingType { return f.findingType }

// EngineID returns the ID of the engine that detected this finding.
func (f *Finding) EngineID() string { return f.engineID }

// RuleID returns the rule ID that triggered this finding.
func (f *Finding) RuleID() string { return f.ruleID }

// Title returns the finding title.
func (f *Finding) Title() string { return f.title }

// Description returns the finding description.
func (f *Finding) Description() string { return f.description }

// NormalizedSeverity returns the severity as normalized by the engine adapter.
func (f *Finding) NormalizedSeverity() Severity { return f.normalizedSeverity }

// EffectiveSeverity returns the severity after policy adjustments.
func (f *Finding) EffectiveSeverity() Severity { return f.effectiveSeverity }

// Confidence returns the detection confidence level.
func (f *Finding) Confidence() Confidence { return f.confidence }

// Reachability returns the reachability status.
func (f *Finding) Reachability() Reachability { return f.reachability }

// Location returns the source code location.
func (f *Finding) Location() Location { return f.location }

// Fingerprint returns the stable fingerprint for this finding.
func (f *Finding) Fingerprint() Fingerprint { return f.fingerprint }

// CWEID returns the CWE identifier, if any.
func (f *Finding) CWEID() string { return f.cweID }

// CVEID returns the CVE identifier, if any.
func (f *Finding) CVEID() string { return f.cveID }

// FixVersion returns the version that fixes the vulnerability, if any.
func (f *Finding) FixVersion() string { return f.fixVersion }

// EvidenceRefs returns references to evidence artifacts.
func (f *Finding) EvidenceRefs() []string { return f.evidenceRefs }

// Metadata returns the metadata map.
func (f *Finding) Metadata() map[string]any { return f.metadata }

// DetectedAt returns the detection timestamp.
func (f *Finding) DetectedAt() time.Time { return f.detectedAt }

// SetEffectiveSeverity updates the effective severity after policy evaluation.
// This is the only mutable operation on a finding.
func (f *Finding) SetEffectiveSeverity(s Severity) {
	f.effectiveSeverity = s
}

// HasCVE returns true if this finding has an associated CVE.
func (f *Finding) HasCVE() bool { return f.cveID != "" }

// HasCWE returns true if this finding has an associated CWE.
func (f *Finding) HasCWE() bool { return f.cweID != "" }

// HasFix returns true if a fix version is known.
func (f *Finding) HasFix() bool { return f.fixVersion != "" }

// IsReachable returns true if the vulnerable code is reachable.
func (f *Finding) IsReachable() bool { return f.reachability.IsReachable() }

// SameAs checks if this finding represents the same issue as another.
// Two findings are the same if they have the same fingerprint.
func (f *Finding) SameAs(other *Finding) bool {
	if other == nil {
		return false
	}
	return f.fingerprint.Equals(other.fingerprint)
}

// generateID creates a unique ID for a finding.
func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp if crypto/rand fails
		return "finding-" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return "finding-" + hex.EncodeToString(b)
}

// findingJSON is the JSON representation of a finding.
type findingJSON struct {
	ID                 string         `json:"id"`
	Type               FindingType    `json:"type"`
	EngineID           string         `json:"engine_id"`
	RuleID             string         `json:"rule_id"`
	Title              string         `json:"title"`
	Description        string         `json:"description,omitempty"`
	NormalizedSeverity Severity       `json:"normalized_severity"`
	EffectiveSeverity  Severity       `json:"effective_severity"`
	Confidence         Confidence     `json:"confidence"`
	Reachability       Reachability   `json:"reachability"`
	Location           Location       `json:"location"`
	Fingerprint        Fingerprint    `json:"fingerprint"`
	CWEID              string         `json:"cwe_id,omitempty"`
	CVEID              string         `json:"cve_id,omitempty"`
	FixVersion         string         `json:"fix_version,omitempty"`
	EvidenceRefs       []string       `json:"evidence_refs,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	DetectedAt         time.Time      `json:"detected_at"`
}

// MarshalJSON implements json.Marshaler.
func (f *Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(findingJSON{
		ID:                 f.id,
		Type:               f.findingType,
		EngineID:           f.engineID,
		RuleID:             f.ruleID,
		Title:              f.title,
		Description:        f.description,
		NormalizedSeverity: f.normalizedSeverity,
		EffectiveSeverity:  f.effectiveSeverity,
		Confidence:         f.confidence,
		Reachability:       f.reachability,
		Location:           f.location,
		Fingerprint:        f.fingerprint,
		CWEID:              f.cweID,
		CVEID:              f.cveID,
		FixVersion:         f.fixVersion,
		EvidenceRefs:       f.evidenceRefs,
		Metadata:           f.metadata,
		DetectedAt:         f.detectedAt,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (f *Finding) UnmarshalJSON(data []byte) error {
	var fj findingJSON
	if err := json.Unmarshal(data, &fj); err != nil {
		return err
	}

	f.id = fj.ID
	f.findingType = fj.Type
	f.engineID = fj.EngineID
	f.ruleID = fj.RuleID
	f.title = fj.Title
	f.description = fj.Description
	f.normalizedSeverity = fj.NormalizedSeverity
	f.effectiveSeverity = fj.EffectiveSeverity
	f.confidence = fj.Confidence
	f.reachability = fj.Reachability
	f.location = fj.Location
	f.fingerprint = fj.Fingerprint
	f.cweID = fj.CWEID
	f.cveID = fj.CVEID
	f.fixVersion = fj.FixVersion
	f.evidenceRefs = fj.EvidenceRefs
	f.metadata = fj.Metadata
	f.detectedAt = fj.DetectedAt

	if f.metadata == nil {
		f.metadata = make(map[string]any)
	}

	return nil
}
