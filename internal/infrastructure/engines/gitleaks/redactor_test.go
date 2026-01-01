package gitleaks

import (
	"strings"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
)

func TestNewRedactor(t *testing.T) {
	redactor := NewRedactor()
	assert.NotNil(t, redactor)
}

func TestNewRedactorWithPatterns(t *testing.T) {
	patterns := []string{"pattern1", "pattern2"}
	redactor := NewRedactorWithPatterns(patterns)

	assert.NotNil(t, redactor)
	assert.Len(t, redactor.customPatterns, 2)
}

func TestRedactor_RedactSecret_Empty(t *testing.T) {
	redactor := NewRedactor()

	result := redactor.RedactSecret("")

	assert.Empty(t, result)
}

func TestRedactor_RedactSecret_Short(t *testing.T) {
	redactor := NewRedactor()

	result := redactor.RedactSecret("short")

	assert.Equal(t, RedactionMarker, result)
}

func TestRedactor_RedactSecret_Long(t *testing.T) {
	redactor := NewRedactor()
	secret := "AKIAIOSFODNN7EXAMPLE"

	result := redactor.RedactSecret(secret)

	// Should show partial content
	assert.Contains(t, result, "AKIA")
	assert.Contains(t, result, "MPLE")
	assert.Contains(t, result, RedactionMarker)
}

func TestRedactor_RedactFully(t *testing.T) {
	redactor := NewRedactor()

	result := redactor.RedactFully("any-secret-value")

	assert.Equal(t, RedactionMarker, result)
}

func TestRedactor_RedactFully_Empty(t *testing.T) {
	redactor := NewRedactor()

	result := redactor.RedactFully("")

	assert.Empty(t, result)
}

func TestRedactor_RedactFinding(t *testing.T) {
	redactor := NewRedactor()
	finding := ports.RawFinding{
		RuleID:  "aws-access-key-id",
		Message: "AWS Access Key ID",
		File:    "config.go",
		Snippet: "key = AKIAIOSFODNN7EXAMPLE",
		Metadata: map[string]string{
			"secret": "AKIAIOSFODNN7EXAMPLE",
			"match":  "AKIAIOSFODNN7EXAMPLE",
		},
	}

	result := redactor.RedactFinding(finding)

	// Secret should be partially redacted in metadata
	assert.Contains(t, result.Metadata["secret"], RedactionMarker)
	// The redacted version should be different from original (partial redaction)
	assert.NotEqual(t, "AKIAIOSFODNN7EXAMPLE", result.Metadata["secret"])

	// Match should be redacted
	assert.Equal(t, RedactionMarker, result.Metadata["match"])

	// Snippet should be redacted
	assert.Contains(t, result.Snippet, RedactionMarker)
	assert.NotContains(t, result.Snippet, "AKIAIOSFODNN7EXAMPLE")
}

func TestRedactor_RedactFinding_NoSecret(t *testing.T) {
	redactor := NewRedactor()
	finding := ports.RawFinding{
		RuleID:   "test-rule",
		Metadata: map[string]string{},
	}

	result := redactor.RedactFinding(finding)

	// Should not panic and return similar finding
	assert.Equal(t, "test-rule", result.RuleID)
}

func TestRedactor_RedactMultiple(t *testing.T) {
	redactor := NewRedactor()
	text := "password=secret1 and api_key=secret2"
	secrets := []string{"secret1", "secret2"}

	result := redactor.RedactMultiple(text, secrets)

	assert.NotContains(t, result, "secret1")
	assert.NotContains(t, result, "secret2")
	assert.Contains(t, result, RedactionMarker)
}

func TestRedactor_RedactMultiple_EmptySecrets(t *testing.T) {
	redactor := NewRedactor()
	text := "no secrets here"

	result := redactor.RedactMultiple(text, nil)

	assert.Equal(t, text, result)
}

func TestIsRedacted(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{RedactionMarker, true},
		{"prefix" + RedactionMarker + "suffix", true},
		{"no redaction", false},
		{"", false},
	}

	for _, tt := range tests {
		result := IsRedacted(tt.input)
		assert.Equal(t, tt.expected, result, "Input: %s", tt.input)
	}
}

func TestCountRedactions(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"no redactions", 0},
		{RedactionMarker, 1},
		{RedactionMarker + " and " + RedactionMarker, 2},
		{"", 0},
	}

	for _, tt := range tests {
		result := CountRedactions(tt.input)
		assert.Equal(t, tt.expected, result, "Input: %s", tt.input)
	}
}

func TestRedactor_redactInContext(t *testing.T) {
	redactor := NewRedactor()

	tests := []struct {
		context  string
		secret   string
		expected string
	}{
		{"password=secret123", "secret123", "password=" + RedactionMarker},
		{"no secret here", "missing", "no secret here"},
		{"", "secret", ""},
		{"has secret", "", "has secret"},
	}

	for _, tt := range tests {
		result := redactor.redactInContext(tt.context, tt.secret)
		assert.Equal(t, tt.expected, result)
	}
}

func TestRedactor_RedactSecret_ExactlyMinLength(t *testing.T) {
	redactor := NewRedactor()
	// Exactly 8 characters (MinSecretLength)
	secret := "12345678"

	result := redactor.RedactSecret(secret)

	// Should use partial redaction
	assert.Contains(t, result, RedactionMarker)
	// Check prefix (2 chars since 8/4 = 2 max visible)
	assert.True(t, strings.HasPrefix(result, "12"))
}

func TestRedactor_RedactSecret_LongSecret(t *testing.T) {
	redactor := NewRedactor()
	// 32 character secret (max visible = 8 chars each side)
	secret := "12345678901234567890123456789012"

	result := redactor.RedactSecret(secret)

	// Should show first 4 and last 4 (VisibleChars = 4, which is < 32/4=8)
	assert.Contains(t, result, "1234")
	assert.Contains(t, result, "9012")
	assert.Contains(t, result, RedactionMarker)
}

func TestRedactor_RedactSecret_VeryShortSecret(t *testing.T) {
	redactor := NewRedactor()
	// 4 character secret - too short for partial redaction
	secret := "1234"

	result := redactor.RedactSecret(secret)

	// Should be fully redacted
	assert.Equal(t, RedactionMarker, result)
}

func TestRedactor_RedactFinding_NilMetadata(t *testing.T) {
	redactor := NewRedactor()
	finding := ports.RawFinding{
		RuleID:   "test-rule",
		Metadata: nil,
	}

	result := redactor.RedactFinding(finding)

	// Should not panic
	assert.Equal(t, "test-rule", result.RuleID)
}

func TestRedactor_RedactFinding_EmptySnippet(t *testing.T) {
	redactor := NewRedactor()
	finding := ports.RawFinding{
		RuleID:  "test-rule",
		Snippet: "",
		Metadata: map[string]string{
			"secret": "mysecret123",
		},
	}

	result := redactor.RedactFinding(finding)

	// Snippet should remain empty
	assert.Empty(t, result.Snippet)
	// But secret in metadata should be redacted
	assert.Contains(t, result.Metadata["secret"], RedactionMarker)
}

func TestRedactor_RedactFinding_NoMatchInMetadata(t *testing.T) {
	redactor := NewRedactor()
	finding := ports.RawFinding{
		RuleID: "test-rule",
		Metadata: map[string]string{
			"secret": "mysecret123",
			// no "match" key
		},
	}

	result := redactor.RedactFinding(finding)

	// Should not panic, secret should be redacted
	assert.Contains(t, result.Metadata["secret"], RedactionMarker)
}

func TestRedactor_RedactFinding_EmptyMatchInMetadata(t *testing.T) {
	redactor := NewRedactor()
	finding := ports.RawFinding{
		RuleID: "test-rule",
		Metadata: map[string]string{
			"secret": "mysecret123",
			"match":  "", // empty match
		},
	}

	result := redactor.RedactFinding(finding)

	// Match should remain empty (not redacted to marker)
	assert.Empty(t, result.Metadata["match"])
}
