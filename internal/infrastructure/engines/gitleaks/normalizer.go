package gitleaks

import (
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Normalizer converts gitleaks raw findings to domain findings.
type Normalizer struct {
	// ruleOverrides allows overriding default severity for specific rules
	ruleOverrides map[string]finding.Severity
}

// NewNormalizer creates a new gitleaks normalizer.
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

// Normalize converts a raw gitleaks finding to a domain finding.
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

	// Secrets detection is typically high confidence
	confidence := finding.ConfidenceHigh

	// Check entropy for confidence adjustment
	if entropy, ok := raw.Metadata["entropy"]; ok {
		// Low entropy might indicate false positive
		if strings.HasPrefix(entropy, "0.") || strings.HasPrefix(entropy, "1.") {
			confidence = finding.ConfidenceMedium
		}
	}

	// Create finding with options
	opts := []finding.FindingOption{
		finding.WithConfidence(confidence),
	}

	// Add CWE for hardcoded secrets
	opts = append(opts, finding.WithCWE("798")) // CWE-798: Use of Hard-coded Credentials

	// Add redacted snippet if available
	if raw.Snippet != "" {
		opts = append(opts, finding.WithMetadata("snippet", raw.Snippet))
	}

	// Add commit info if available (for git mode)
	if commit, ok := raw.Metadata["commit"]; ok && commit != "" {
		opts = append(opts, finding.WithMetadata("commit", commit))
	}

	// Add gitleaks fingerprint
	if fp, ok := raw.Metadata["gitleaks_fingerprint"]; ok && fp != "" {
		opts = append(opts, finding.WithMetadata("gitleaks_fingerprint", fp))
	}

	return finding.NewFinding(
		finding.FindingTypeSecret,
		string(engineID),
		raw.RuleID,
		raw.Message,
		severity,
		loc,
		opts...,
	)
}

// normalizeSeverity converts gitleaks severity to domain severity.
func (n *Normalizer) normalizeSeverity(ruleID, rawSeverity string) finding.Severity {
	// Check for rule-specific override first
	if override, ok := n.ruleOverrides[ruleID]; ok {
		return override
	}

	// All secrets are at least HIGH severity by default
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
		return finding.SeverityHigh // Default for secrets
	}
}

// defaultRuleOverrides returns severity overrides for specific gitleaks rules.
func defaultRuleOverrides() map[string]finding.Severity {
	return map[string]finding.Severity{
		// Cloud provider credentials - CRITICAL
		"aws-access-key-id":     finding.SeverityCritical,
		"aws-secret-access-key": finding.SeverityCritical,
		"gcp-api-key":           finding.SeverityCritical,
		"google-api-key":        finding.SeverityCritical,
		"azure-storage-key":     finding.SeverityCritical,

		// Private keys - CRITICAL
		"private-key":        finding.SeverityCritical,
		"rsa-private-key":    finding.SeverityCritical,
		"ssh-private-key":    finding.SeverityCritical,
		"openssh-private-key": finding.SeverityCritical,
		"pgp-private-key":    finding.SeverityCritical,

		// API tokens for major services - CRITICAL
		"github-pat":          finding.SeverityCritical,
		"github-oauth":        finding.SeverityCritical,
		"gitlab-pat":          finding.SeverityCritical,
		"slack-token":         finding.SeverityCritical,
		"slack-webhook":       finding.SeverityHigh,
		"stripe-api-key":      finding.SeverityCritical,
		"twilio-api-key":      finding.SeverityCritical,
		"sendgrid-api-key":    finding.SeverityCritical,

		// Database credentials - CRITICAL
		"mongodb-uri":         finding.SeverityCritical,
		"postgres-uri":        finding.SeverityCritical,
		"mysql-uri":           finding.SeverityCritical,

		// JWT and encryption keys - HIGH
		"jwt-secret":          finding.SeverityHigh,
		"encryption-key":      finding.SeverityHigh,

		// Generic patterns - HIGH (might be false positives)
		"generic-api-key":     finding.SeverityHigh,
		"generic-secret":      finding.SeverityHigh,
		"password-in-url":     finding.SeverityHigh,
	}
}

// GetRuleDescription returns a human-readable description for a gitleaks rule.
func GetRuleDescription(ruleID string) string {
	descriptions := map[string]string{
		"aws-access-key-id":     "AWS Access Key ID",
		"aws-secret-access-key": "AWS Secret Access Key",
		"gcp-api-key":           "GCP API Key",
		"google-api-key":        "Google API Key",
		"azure-storage-key":     "Azure Storage Key",
		"private-key":           "Private Key",
		"rsa-private-key":       "RSA Private Key",
		"ssh-private-key":       "SSH Private Key",
		"github-pat":            "GitHub Personal Access Token",
		"gitlab-pat":            "GitLab Personal Access Token",
		"slack-token":           "Slack Token",
		"stripe-api-key":        "Stripe API Key",
		"generic-api-key":       "Generic API Key",
		"generic-secret":        "Generic Secret",
	}

	if desc, ok := descriptions[ruleID]; ok {
		return desc
	}
	return "Secret detected"
}
