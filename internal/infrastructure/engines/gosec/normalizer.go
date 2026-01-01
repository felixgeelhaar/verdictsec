package gosec

import (
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Normalizer converts gosec raw findings to domain findings.
type Normalizer struct {
	// ruleOverrides allows overriding default severity for specific rules
	ruleOverrides map[string]finding.Severity
}

// NewNormalizer creates a new gosec normalizer.
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

// Normalize converts a raw gosec finding to a domain finding.
func (n *Normalizer) Normalize(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding {
	// Create location
	loc := finding.NewLocation(
		raw.File,
		raw.StartLine,
		raw.StartColumn,
		raw.EndLine,
		raw.EndColumn,
	)

	// Determine severity
	severity := n.normalizeSeverity(raw.RuleID, raw.Severity)

	// Determine confidence
	confidence := normalizeConfidence(raw.Confidence)

	// Create finding with options
	opts := []finding.FindingOption{
		finding.WithConfidence(confidence),
	}

	// Add CWE if available
	if cweID, ok := raw.Metadata["cwe_id"]; ok && cweID != "" {
		opts = append(opts, finding.WithCWE(cweID))
	}

	// Add snippet as metadata if available
	if raw.Snippet != "" {
		opts = append(opts, finding.WithMetadata("snippet", raw.Snippet))
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

// normalizeSeverity converts gosec severity to domain severity.
// It also checks for rule-specific overrides.
func (n *Normalizer) normalizeSeverity(ruleID, rawSeverity string) finding.Severity {
	// Check for rule-specific override first
	if override, ok := n.ruleOverrides[ruleID]; ok {
		return override
	}

	// Map gosec severity to domain severity
	switch strings.ToUpper(rawSeverity) {
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

// normalizeConfidence converts gosec confidence to domain confidence.
func normalizeConfidence(rawConfidence string) finding.Confidence {
	switch strings.ToUpper(rawConfidence) {
	case "HIGH":
		return finding.ConfidenceHigh
	case "MEDIUM":
		return finding.ConfidenceMedium
	case "LOW":
		return finding.ConfidenceLow
	default:
		return finding.ConfidenceUnknown
	}
}

// defaultRuleOverrides returns severity overrides for specific gosec rules.
// This allows fine-tuning of severity based on real-world risk assessment.
func defaultRuleOverrides() map[string]finding.Severity {
	return map[string]finding.Severity{
		// Cryptography issues - typically high risk
		"G401": finding.SeverityHigh,   // Use of weak cryptographic primitive
		"G402": finding.SeverityHigh,   // TLS InsecureSkipVerify
		"G403": finding.SeverityHigh,   // RSA key < 2048 bits
		"G404": finding.SeverityMedium, // Insecure random number source

		// Injection vulnerabilities - high risk
		"G101": finding.SeverityCritical, // Hardcoded credentials
		"G102": finding.SeverityHigh,     // Bind to all interfaces
		"G103": finding.SeverityMedium,   // Audit unsafe block
		"G104": finding.SeverityLow,      // Audit errors not checked
		"G106": finding.SeverityHigh,     // SSH InsecureIgnoreHostKey
		"G107": finding.SeverityHigh,     // URL provided to HTTP request as taint input
		"G108": finding.SeverityMedium,   // Profiling endpoint automatically exposed
		"G109": finding.SeverityMedium,   // Integer overflow
		"G110": finding.SeverityMedium,   // Decompression bomb

		// File permissions
		"G301": finding.SeverityMedium, // Poor file permissions
		"G302": finding.SeverityMedium, // Poor file permissions on chmod
		"G303": finding.SeverityMedium, // Creating tempfile with predictable path
		"G304": finding.SeverityHigh,   // File path provided as taint input
		"G305": finding.SeverityHigh,   // File traversal when extracting zip
		"G306": finding.SeverityMedium, // Poor file permissions on WriteFile
		"G307": finding.SeverityLow,    // Defer in loop

		// SQL injection
		"G201": finding.SeverityCritical, // SQL query construction using format string
		"G202": finding.SeverityCritical, // SQL query construction using string concatenation
		"G203": finding.SeverityHigh,     // Template injection

		// Memory safety
		"G501": finding.SeverityHigh, // Import blocklist: crypto/md5
		"G502": finding.SeverityHigh, // Import blocklist: crypto/des
		"G503": finding.SeverityHigh, // Import blocklist: crypto/rc4
		"G504": finding.SeverityHigh, // Import blocklist: net/http/cgi
		"G505": finding.SeverityHigh, // Import blocklist: crypto/sha1

		// Command execution
		"G204": finding.SeverityCritical, // Subprocess launched with variable

	}
}

// GetRuleDescription returns a human-readable description for a gosec rule.
func GetRuleDescription(ruleID string) string {
	descriptions := map[string]string{
		"G101": "Hardcoded credentials",
		"G102": "Bind to all interfaces",
		"G103": "Audit use of unsafe block",
		"G104": "Audit errors not checked",
		"G106": "SSH InsecureIgnoreHostKey",
		"G107": "URL provided to HTTP request as taint input",
		"G108": "Profiling endpoint automatically exposed",
		"G109": "Integer overflow",
		"G110": "Decompression bomb",
		"G201": "SQL query construction using format string",
		"G202": "SQL query construction using string concatenation",
		"G203": "Template injection",
		"G204": "Subprocess launched with variable",
		"G301": "Poor file permissions",
		"G302": "Poor file permissions on chmod",
		"G303": "Creating tempfile with predictable path",
		"G304": "File path provided as taint input",
		"G305": "File traversal when extracting zip",
		"G306": "Poor file permissions on WriteFile",
		"G307": "Defer in loop",
		"G401": "Use of weak cryptographic primitive",
		"G402": "TLS InsecureSkipVerify",
		"G403": "RSA key smaller than 2048 bits",
		"G404": "Insecure random number source",
		"G501": "Import blocklist: crypto/md5",
		"G502": "Import blocklist: crypto/des",
		"G503": "Import blocklist: crypto/rc4",
		"G504": "Import blocklist: net/http/cgi",
		"G505": "Import blocklist: crypto/sha1",
	}

	if desc, ok := descriptions[ruleID]; ok {
		return desc
	}
	return "Unknown gosec rule"
}

// Ensure Normalizer implements usecases.FindingNormalizer
// Note: We verify the interface at compile time in tests
