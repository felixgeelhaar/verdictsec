package staticcheck

import (
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Normalizer converts staticcheck raw findings to domain findings.
type Normalizer struct {
	// ruleOverrides allows overriding default severity for specific rules
	ruleOverrides map[string]finding.Severity
}

// NewNormalizer creates a new staticcheck normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{
		ruleOverrides: defaultRuleOverrides(),
	}
}

// NewNormalizerWithOverrides creates a normalizer with custom rule overrides.
func NewNormalizerWithOverrides(overrides map[string]finding.Severity) *Normalizer {
	merged := defaultRuleOverrides()
	for k, v := range overrides {
		merged[k] = v
	}
	return &Normalizer{
		ruleOverrides: merged,
	}
}

// Normalize converts a raw staticcheck finding to a domain finding.
func (n *Normalizer) Normalize(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding {
	// Create location
	loc := finding.NewLocation(
		raw.File,
		raw.StartLine,
		raw.StartColumn,
		raw.EndLine,
		raw.EndColumn,
	)

	// Determine severity - dead code is informational by default
	severity := n.normalizeSeverity(raw.RuleID)

	// Determine confidence - staticcheck has high confidence
	confidence := finding.ConfidenceHigh

	// Create finding with options
	opts := []finding.FindingOption{
		finding.WithConfidence(confidence),
	}

	// Add check code as metadata
	if checkCode, ok := raw.Metadata["check_code"]; ok && checkCode != "" {
		opts = append(opts, finding.WithMetadata("check_code", checkCode))
	}

	return finding.NewFinding(
		finding.FindingTypeSAST,
		string(engineID),
		raw.RuleID,
		raw.Message,
		severity,
		loc,
		opts...,
	)
}

// normalizeSeverity returns the severity for a staticcheck rule.
// Dead code findings are informational by default.
func (n *Normalizer) normalizeSeverity(ruleID string) finding.Severity {
	// Check for rule-specific override first
	if override, ok := n.ruleOverrides[ruleID]; ok {
		return override
	}

	// Default: dead code is informational
	return finding.SeverityInfo
}

// defaultRuleOverrides returns severity overrides for specific staticcheck rules.
// For U1000 (dead code), we keep it as Info since it's not a security issue.
func defaultRuleOverrides() map[string]finding.Severity {
	return map[string]finding.Severity{
		// U1000 - unused code (functions, types, constants, variables)
		// This is informational, not a security issue
		"U1000": finding.SeverityInfo,
	}
}

// GetRuleDescription returns a human-readable description for a staticcheck rule.
func GetRuleDescription(ruleID string) string {
	descriptions := map[string]string{
		"U1000": "Unused code (functions, types, constants, variables)",
	}

	if desc, ok := descriptions[ruleID]; ok {
		return desc
	}
	return "Unknown staticcheck rule"
}

// Ensure Normalizer can be used by the composite normalizer
// Note: We verify the interface at compile time in tests
