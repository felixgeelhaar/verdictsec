package license

import (
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Normalizer converts go-licenses findings to domain findings.
type Normalizer struct{}

// NewNormalizer creates a new license normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// Normalize converts a raw license finding to a domain finding.
func (n *Normalizer) Normalize(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding {
	severity := mapSeverity(raw.Severity)
	loc := finding.NewLocation("go.mod", 1, 0, 0, 0)

	// Extract metadata
	module := raw.Metadata["module"]
	license := raw.Metadata["license"]
	licenseURL := raw.Metadata["license_url"]

	f := finding.NewFinding(
		finding.FindingTypeLicense,
		string(engineID),
		raw.RuleID,
		raw.Message,
		severity,
		loc,
		finding.WithConfidence(finding.ConfidenceHigh),
		finding.WithMetadata("module", module),
		finding.WithMetadata("license", license),
		finding.WithMetadata("license_url", licenseURL),
	)

	return f
}

// mapSeverity maps string severity to domain severity.
func mapSeverity(s string) finding.Severity {
	switch s {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityUnknown
	}
}
