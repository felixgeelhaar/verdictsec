package semgrep

import (
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Normalizer converts semgrep findings to domain findings.
type Normalizer struct{}

// NewNormalizer creates a new semgrep normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// Normalize converts a raw semgrep finding to a domain finding.
func (n *Normalizer) Normalize(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding {
	severity := mapSeverity(raw.Severity)
	confidence := mapConfidence(raw.Confidence)
	loc := finding.NewLocation(raw.File, raw.StartLine, raw.StartColumn, raw.EndLine, raw.EndColumn)

	// Build options
	opts := []finding.FindingOption{
		finding.WithConfidence(confidence),
	}

	// Add snippet as metadata if available
	if raw.Snippet != "" {
		opts = append(opts, finding.WithMetadata("snippet", raw.Snippet))
	}

	// Add CWE if present
	if cwe, ok := raw.Metadata["cwe"]; ok && cwe != "" {
		opts = append(opts, finding.WithCWE(cwe))
	}

	// Add fix suggestion if present
	if fix, ok := raw.Metadata["fix"]; ok && fix != "" {
		opts = append(opts, finding.WithMetadata("fix", fix))
	}

	f := finding.NewFinding(
		finding.FindingTypeSAST,
		string(engineID),
		raw.RuleID,
		raw.Message,
		severity,
		loc,
		opts...,
	)

	return f
}

// mapSeverity maps string severity to domain severity.
func mapSeverity(s string) finding.Severity {
	switch strings.ToUpper(s) {
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

// mapConfidence maps string confidence to domain confidence.
func mapConfidence(s string) finding.Confidence {
	switch strings.ToUpper(s) {
	case "HIGH":
		return finding.ConfidenceHigh
	case "MEDIUM":
		return finding.ConfidenceMedium
	case "LOW":
		return finding.ConfidenceLow
	default:
		return finding.ConfidenceMedium
	}
}
