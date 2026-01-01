package govulncheck

import (
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Normalizer converts govulncheck raw findings to domain findings.
type Normalizer struct {
	ruleOverrides map[string]finding.Severity
}

// NewNormalizer creates a new govulncheck normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{
		ruleOverrides: map[string]finding.Severity{},
	}
}

// NewNormalizerWithOverrides creates a normalizer with custom rule overrides.
func NewNormalizerWithOverrides(overrides map[string]finding.Severity) *Normalizer {
	if overrides == nil {
		overrides = map[string]finding.Severity{}
	}
	return &Normalizer{
		ruleOverrides: overrides,
	}
}

// Normalize converts a raw govulncheck finding to a domain finding.
func (n *Normalizer) Normalize(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding {
	// Create location
	loc := finding.NewLocation(
		raw.File,
		raw.StartLine,
		raw.StartColumn,
		raw.EndLine,
		raw.EndColumn,
	)

	// Determine severity - check overrides first, then default mapping
	severity := n.normalizeSeverity(raw.RuleID, raw.Severity)

	// Determine confidence
	confidence := normalizeConfidence(raw.Confidence)

	// Determine reachability from trace
	reachability := finding.ReachabilityUnknown
	if _, hasFunc := raw.Metadata["vulnerable_function"]; hasFunc {
		// If we have a function in the trace, it's reachable
		reachability = finding.ReachabilityReachable
	}

	// Create finding with options
	opts := []finding.FindingOption{
		finding.WithConfidence(confidence),
		finding.WithReachability(reachability),
	}

	// Add CVE if available
	if cveID, ok := raw.Metadata["cve_id"]; ok && cveID != "" {
		opts = append(opts, finding.WithCVE(cveID))
	}

	// Add OSV ID as metadata
	if osvID, ok := raw.Metadata["osv_id"]; ok && osvID != "" {
		opts = append(opts, finding.WithMetadata("osv_id", osvID))
	}

	// Add module info
	if module, ok := raw.Metadata["vulnerable_module"]; ok && module != "" {
		opts = append(opts, finding.WithMetadata("module", module))
	}

	if version, ok := raw.Metadata["vulnerable_version"]; ok && version != "" {
		opts = append(opts, finding.WithMetadata("version", version))
	}

	// Add fix version if available
	if fixVersion, ok := raw.Metadata["fix_version"]; ok && fixVersion != "" {
		opts = append(opts, finding.WithFixVersion(fixVersion))
	}

	// Add description from details
	if details, ok := raw.Metadata["details"]; ok && details != "" {
		opts = append(opts, finding.WithDescription(details))
	}

	return finding.NewFinding(
		finding.FindingTypeVuln,
		string(engineID),
		raw.RuleID,
		raw.Message,
		severity,
		loc,
		opts...,
	)
}

// normalizeSeverity converts govulncheck severity to domain severity.
// It checks for rule-specific overrides first.
func (n *Normalizer) normalizeSeverity(ruleID, rawSeverity string) finding.Severity {
	// Check for rule-specific override first
	if override, ok := n.ruleOverrides[ruleID]; ok {
		return override
	}

	switch strings.ToUpper(rawSeverity) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		// Default vulnerabilities to HIGH if unknown
		return finding.SeverityHigh
	}
}

// normalizeConfidence converts govulncheck confidence to domain confidence.
func normalizeConfidence(rawConfidence string) finding.Confidence {
	switch strings.ToUpper(rawConfidence) {
	case "HIGH":
		return finding.ConfidenceHigh
	case "MEDIUM":
		return finding.ConfidenceMedium
	case "LOW":
		return finding.ConfidenceLow
	default:
		return finding.ConfidenceHigh // Govulncheck findings are generally high confidence
	}
}
