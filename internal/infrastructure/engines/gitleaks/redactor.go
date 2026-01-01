package gitleaks

import (
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

const (
	// RedactionMarker is the placeholder for redacted content.
	RedactionMarker = "[REDACTED]"

	// MinSecretLength is the minimum length to attempt partial redaction.
	MinSecretLength = 8

	// VisibleChars is the number of characters to show at start and end.
	VisibleChars = 4
)

// Redactor handles secret redaction in findings.
type Redactor struct {
	// customPatterns allows adding custom redaction patterns
	customPatterns []string
}

// NewRedactor creates a new Redactor.
func NewRedactor() *Redactor {
	return &Redactor{
		customPatterns: []string{},
	}
}

// NewRedactorWithPatterns creates a Redactor with custom patterns.
func NewRedactorWithPatterns(patterns []string) *Redactor {
	return &Redactor{
		customPatterns: patterns,
	}
}

// RedactFinding redacts sensitive information from a finding.
func (r *Redactor) RedactFinding(finding ports.RawFinding) ports.RawFinding {
	// Create a copy to avoid modifying the original
	redacted := finding

	// Get the secret to redact
	secret := ""
	if s, ok := finding.Metadata["secret"]; ok {
		secret = s
	}

	// Redact the secret in metadata
	if secret != "" {
		redactedSecret := r.RedactSecret(secret)
		if redacted.Metadata == nil {
			redacted.Metadata = make(map[string]string)
		}
		redacted.Metadata["secret"] = redactedSecret
	}

	// Redact the match in metadata
	if match, ok := finding.Metadata["match"]; ok && match != "" {
		redacted.Metadata["match"] = r.redactInContext(match, secret)
	}

	// Redact the snippet
	if finding.Snippet != "" && secret != "" {
		redacted.Snippet = r.redactInContext(finding.Snippet, secret)
	}

	return redacted
}

// RedactSecret redacts a secret value, optionally showing partial content.
func (r *Redactor) RedactSecret(secret string) string {
	if secret == "" {
		return ""
	}

	length := len(secret)

	// For very short secrets, fully redact
	if length < MinSecretLength {
		return RedactionMarker
	}

	// For longer secrets, show first and last few chars
	// e.g., "sk-abc...xyz" for "sk-abcdefghijklmnoxyz"
	visibleStart := VisibleChars
	visibleEnd := VisibleChars

	// Don't show more than 25% of the secret
	maxVisible := length / 4
	if visibleStart > maxVisible {
		visibleStart = maxVisible
	}
	if visibleEnd > maxVisible {
		visibleEnd = maxVisible
	}

	// Minimum of 1 char on each side if secret is long enough
	if visibleStart < 1 && length >= 4 {
		visibleStart = 1
	}
	if visibleEnd < 1 && length >= 4 {
		visibleEnd = 1
	}

	start := secret[:visibleStart]
	end := secret[length-visibleEnd:]

	return start + "..." + RedactionMarker + "..." + end
}

// RedactFully completely redacts a secret.
func (r *Redactor) RedactFully(secret string) string {
	if secret == "" {
		return ""
	}
	return RedactionMarker
}

// redactInContext redacts a secret within a larger string context.
func (r *Redactor) redactInContext(context, secret string) string {
	if secret == "" || context == "" {
		return context
	}

	// Replace the secret with a redaction marker
	redacted := strings.ReplaceAll(context, secret, RedactionMarker)

	return redacted
}

// RedactMultiple redacts multiple secrets from a string.
func (r *Redactor) RedactMultiple(text string, secrets []string) string {
	result := text
	for _, secret := range secrets {
		if secret != "" {
			result = strings.ReplaceAll(result, secret, RedactionMarker)
		}
	}
	return result
}

// IsRedacted checks if a string contains redaction markers.
func IsRedacted(s string) bool {
	return strings.Contains(s, RedactionMarker)
}

// CountRedactions counts the number of redaction markers in a string.
func CountRedactions(s string) int {
	return strings.Count(s, RedactionMarker)
}
