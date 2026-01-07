// Package trivy provides an adapter for the Trivy security scanner.
package trivy

import (
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Normalizer converts Trivy raw findings to domain findings.
type Normalizer struct{}

// NewNormalizer creates a new Trivy normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// EngineID returns the engine ID this normalizer handles.
func (n *Normalizer) EngineID() ports.EngineID {
	return ports.EngineTrivy
}

// Normalize converts a raw finding to a domain finding.
func (n *Normalizer) Normalize(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding {
	// Determine finding type based on metadata
	findingType := n.determineFindingType(raw.Metadata)

	// Convert severity
	severity := n.normalizeSeverity(raw.Severity)

	// Convert confidence
	confidence := n.normalizeConfidence(raw.Confidence)

	// Build location
	endLine := raw.EndLine
	if endLine == 0 {
		endLine = raw.StartLine
	}
	endColumn := raw.EndColumn
	if endColumn == 0 {
		endColumn = raw.StartColumn
	}
	loc := finding.NewLocation(raw.File, raw.StartLine, raw.StartColumn, endLine, endColumn)

	// Build title
	title := n.buildTitle(raw)

	// Build finding with options
	opts := []finding.FindingOption{
		finding.WithDescription(raw.Message),
		finding.WithConfidence(confidence),
	}

	// Add CWE if present
	if cwe, ok := raw.Metadata["cwe"]; ok && cwe != "" {
		opts = append(opts, finding.WithCWE(cwe))
	}

	// Add CVE for vulnerabilities
	if raw.Metadata["type"] == "vulnerability" {
		opts = append(opts, finding.WithCVE(raw.RuleID))
	}

	// Add fix version if present
	if fixVersion, ok := raw.Metadata["fixed_version"]; ok && fixVersion != "" {
		opts = append(opts, finding.WithFixVersion(fixVersion))
	}

	// Add URL as metadata if present
	if url, ok := raw.Metadata["url"]; ok && url != "" {
		opts = append(opts, finding.WithMetadata("url", url))
	}

	// Add package info as metadata for vulnerabilities
	if pkgName, ok := raw.Metadata["package"]; ok && pkgName != "" {
		opts = append(opts, finding.WithMetadata("package", pkgName))
	}
	if installedVersion, ok := raw.Metadata["installed_version"]; ok && installedVersion != "" {
		opts = append(opts, finding.WithMetadata("installed_version", installedVersion))
	}

	// Add snippet as metadata if available
	if raw.Snippet != "" {
		opts = append(opts, finding.WithMetadata("snippet", raw.Snippet))
	}

	return finding.NewFinding(
		findingType,
		string(engineID),
		raw.RuleID,
		title,
		severity,
		loc,
		opts...,
	)
}

// determineFindingType determines the finding type from metadata.
func (n *Normalizer) determineFindingType(metadata map[string]string) finding.FindingType {
	if metadata == nil {
		return finding.FindingTypeVuln
	}

	switch metadata["type"] {
	case "vulnerability":
		return finding.FindingTypeVuln
	case "secret":
		return finding.FindingTypeSecret
	default:
		return finding.FindingTypeVuln
	}
}

// buildTitle creates a descriptive title for the finding.
func (n *Normalizer) buildTitle(raw ports.RawFinding) string {
	if raw.Metadata == nil {
		return raw.Message
	}

	switch raw.Metadata["type"] {
	case "vulnerability":
		pkgName := raw.Metadata["package"]
		vulnID := raw.RuleID
		if pkgName != "" {
			return vulnID + " in " + pkgName
		}
		return vulnID
	case "secret":
		return raw.Message
	default:
		return raw.Message
	}
}

// normalizeSeverity converts Trivy severity to domain severity.
func (n *Normalizer) normalizeSeverity(sev string) finding.Severity {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	case "UNKNOWN":
		return finding.SeverityUnknown
	default:
		return finding.SeverityUnknown
	}
}

// normalizeConfidence converts Trivy confidence to domain confidence.
func (n *Normalizer) normalizeConfidence(conf string) finding.Confidence {
	switch strings.ToUpper(conf) {
	case "HIGH":
		return finding.ConfidenceHigh
	case "MEDIUM":
		return finding.ConfidenceMedium
	case "LOW":
		return finding.ConfidenceLow
	default:
		return finding.ConfidenceHigh // Default to high for Trivy
	}
}
