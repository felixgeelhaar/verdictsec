// Package redact provides utilities for redacting sensitive data.
package redact

import (
	"regexp"
	"strings"
)

const (
	// RedactedPlaceholder is the default placeholder for redacted content.
	RedactedPlaceholder = "[REDACTED]"

	// RedactedPartialPrefix shows the first few characters.
	RedactedPartialPrefix = 4

	// RedactedPartialSuffix shows the last few characters.
	RedactedPartialSuffix = 4
)

// Redactor handles secret redaction with configurable options.
type Redactor struct {
	placeholder string
	showPartial bool
	prefixLen   int
	suffixLen   int
	patterns    []*regexp.Regexp
}

// Option configures the redactor.
type Option func(*Redactor)

// WithPlaceholder sets a custom placeholder string.
func WithPlaceholder(placeholder string) Option {
	return func(r *Redactor) {
		r.placeholder = placeholder
	}
}

// WithPartialDisplay shows first and last characters of the secret.
func WithPartialDisplay(prefixLen, suffixLen int) Option {
	return func(r *Redactor) {
		r.showPartial = true
		r.prefixLen = prefixLen
		r.suffixLen = suffixLen
	}
}

// WithPatterns adds regex patterns for automatic redaction.
func WithPatterns(patterns ...*regexp.Regexp) Option {
	return func(r *Redactor) {
		r.patterns = append(r.patterns, patterns...)
	}
}

// New creates a new Redactor with the given options.
func New(opts ...Option) *Redactor {
	r := &Redactor{
		placeholder: RedactedPlaceholder,
		showPartial: false,
		prefixLen:   RedactedPartialPrefix,
		suffixLen:   RedactedPartialSuffix,
		patterns:    defaultPatterns(),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// defaultPatterns returns common secret patterns.
func defaultPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// AWS Access Key ID
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		// AWS Secret Access Key
		regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key['":\s]*[=:\s]['"]?([A-Za-z0-9/+=]{40})['"]?`),
		// GitHub Token
		regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
		// Generic API Key patterns
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)['":\s]*[=:\s]['"]?([A-Za-z0-9_-]{20,})['"]?`),
		// Bearer tokens
		regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_.-]{20,}`),
		// Private key headers
		regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY-----`),
		// JWT tokens
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`),
		// Slack tokens
		regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]+`),
	}
}

// Redact replaces a secret value with a redacted version.
func (r *Redactor) Redact(secret string) string {
	if secret == "" {
		return ""
	}

	if r.showPartial {
		return r.partialRedact(secret)
	}

	return r.placeholder
}

// partialRedact shows first and last characters with asterisks in between.
func (r *Redactor) partialRedact(secret string) string {
	length := len(secret)

	// If too short, just redact completely
	if length <= r.prefixLen+r.suffixLen {
		return r.placeholder
	}

	prefix := secret[:r.prefixLen]
	suffix := secret[length-r.suffixLen:]
	middle := strings.Repeat("*", length-r.prefixLen-r.suffixLen)

	return prefix + middle + suffix
}

// RedactString scans a string for secrets and redacts them.
func (r *Redactor) RedactString(input string) string {
	result := input

	for _, pattern := range r.patterns {
		result = pattern.ReplaceAllStringFunc(result, func(match string) string {
			if r.showPartial {
				return r.partialRedact(match)
			}
			return r.placeholder
		})
	}

	return result
}

// RedactMap redacts values in a map that appear to be secrets.
func (r *Redactor) RedactMap(m map[string]any) map[string]any {
	result := make(map[string]any)

	for key, value := range m {
		if r.isSensitiveKey(key) {
			if str, ok := value.(string); ok {
				result[key] = r.Redact(str)
			} else {
				result[key] = r.placeholder
			}
		} else if str, ok := value.(string); ok {
			result[key] = r.RedactString(str)
		} else if nested, ok := value.(map[string]any); ok {
			result[key] = r.RedactMap(nested)
		} else {
			result[key] = value
		}
	}

	return result
}

// isSensitiveKey checks if a map key suggests sensitive content.
func (r *Redactor) isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	sensitiveWords := []string{
		"secret", "password", "passwd", "pwd", "token",
		"api_key", "apikey", "api-key", "private_key",
		"privatekey", "private-key", "credential", "auth",
		"key", "access_key", "accesskey", "access-key",
	}

	for _, word := range sensitiveWords {
		if strings.Contains(lower, word) {
			return true
		}
	}

	return false
}

// Default is a pre-configured redactor with partial display.
var Default = New(WithPartialDisplay(4, 4))

// Redact uses the default redactor to redact a secret.
func Redact(secret string) string {
	return Default.Redact(secret)
}

// RedactFull completely redacts a secret without showing partial content.
func RedactFull(secret string) string {
	return New().Redact(secret)
}

// RedactString uses the default redactor to scan and redact secrets.
func RedactString(input string) string {
	return Default.RedactString(input)
}
