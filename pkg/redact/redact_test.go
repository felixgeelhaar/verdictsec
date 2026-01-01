package redact

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	r := New()

	assert.NotNil(t, r)
	assert.Equal(t, RedactedPlaceholder, r.placeholder)
	assert.False(t, r.showPartial)
	assert.NotEmpty(t, r.patterns)
}

func TestNewWithOptions(t *testing.T) {
	r := New(
		WithPlaceholder("***HIDDEN***"),
		WithPartialDisplay(2, 3),
	)

	assert.Equal(t, "***HIDDEN***", r.placeholder)
	assert.True(t, r.showPartial)
	assert.Equal(t, 2, r.prefixLen)
	assert.Equal(t, 3, r.suffixLen)
}

func TestWithPatterns(t *testing.T) {
	customPattern := regexp.MustCompile(`custom-[0-9]+`)
	r := New(WithPatterns(customPattern))

	// Should have default patterns plus the custom one
	assert.Greater(t, len(r.patterns), 1)
}

func TestRedact_Empty(t *testing.T) {
	r := New()

	result := r.Redact("")
	assert.Equal(t, "", result)
}

func TestRedact_FullRedaction(t *testing.T) {
	r := New()

	result := r.Redact("my-secret-value")
	assert.Equal(t, RedactedPlaceholder, result)
}

func TestRedact_PartialRedaction(t *testing.T) {
	r := New(WithPartialDisplay(4, 4))

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "long secret",
			input:    "my-super-secret-api-key",
			expected: "my-s***************-key",
		},
		{
			name:     "exactly at threshold",
			input:    "12345678",
			expected: RedactedPlaceholder, // 8 chars = 4+4, so fully redacted
		},
		{
			name:     "short secret",
			input:    "short",
			expected: RedactedPlaceholder, // Too short for partial
		},
		{
			name:     "just over threshold",
			input:    "123456789",
			expected: "1234*6789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.Redact(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedactString_NoSecrets(t *testing.T) {
	r := New()

	input := "This is a normal string without any secrets"
	result := r.RedactString(input)
	assert.Equal(t, input, result)
}

func TestRedactString_AWSAccessKey(t *testing.T) {
	r := New()

	input := "AWS key: AKIAIOSFODNN7EXAMPLE"
	result := r.RedactString(input)
	assert.Contains(t, result, RedactedPlaceholder)
	assert.NotContains(t, result, "AKIAIOSFODNN7EXAMPLE")
}

func TestRedactString_GitHubToken(t *testing.T) {
	r := New()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "ghp token",
			input: "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890",
		},
		{
			name:  "github_pat token",
			input: "pat: github_pat_12345678901234567890ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.RedactString(tt.input)
			assert.Contains(t, result, RedactedPlaceholder)
		})
	}
}

func TestRedactString_JWT(t *testing.T) {
	r := New()

	// Valid JWT format
	input := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	result := r.RedactString(input)
	assert.NotContains(t, result, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
}

func TestRedactString_SlackToken(t *testing.T) {
	r := New()

	input := "slack: xoxb-FAKE-TEST-TOKEN-000000000000-xxxxxxxxxxxxxxxxx"
	result := r.RedactString(input)
	assert.Contains(t, result, RedactedPlaceholder)
}

func TestRedactString_PrivateKey(t *testing.T) {
	r := New()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "RSA private key",
			input: "-----BEGIN RSA PRIVATE KEY-----",
		},
		{
			name:  "EC private key",
			input: "-----BEGIN EC PRIVATE KEY-----",
		},
		{
			name:  "generic private key",
			input: "-----BEGIN PRIVATE KEY-----",
		},
		{
			name:  "OpenSSH private key",
			input: "-----BEGIN OPENSSH PRIVATE KEY-----",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.RedactString(tt.input)
			assert.Contains(t, result, RedactedPlaceholder)
		})
	}
}

func TestRedactString_APIKey(t *testing.T) {
	r := New()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "api_key format",
			input: "api_key=abcdefghijklmnopqrstuvwxyz",
		},
		{
			name:  "apikey format",
			input: "apikey: 12345678901234567890abcd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.RedactString(tt.input)
			assert.Contains(t, result, RedactedPlaceholder)
		})
	}
}

func TestRedactString_PartialDisplay(t *testing.T) {
	r := New(WithPartialDisplay(4, 4))

	input := "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	result := r.RedactString(input)

	// Should show partial redaction
	assert.NotEqual(t, input, result)
}

func TestRedactMap_Empty(t *testing.T) {
	r := New()

	result := r.RedactMap(map[string]any{})
	assert.Empty(t, result)
}

func TestRedactMap_NoSensitiveKeys(t *testing.T) {
	r := New()

	input := map[string]any{
		"name":  "test",
		"value": 123,
	}
	result := r.RedactMap(input)

	assert.Equal(t, "test", result["name"])
	assert.Equal(t, 123, result["value"])
}

func TestRedactMap_SensitiveKeys(t *testing.T) {
	r := New()

	tests := []struct {
		name string
		key  string
	}{
		{"secret", "secret"},
		{"password", "password"},
		{"api_key", "api_key"},
		{"token", "auth_token"},
		{"private_key", "private_key"},
		{"credential", "credential"},
		{"access_key", "access_key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := map[string]any{
				tt.key: "sensitive-value-here",
			}
			result := r.RedactMap(input)

			// Value should be redacted
			assert.Contains(t, result[tt.key], "[REDACTED]")
		})
	}
}

func TestRedactMap_SensitiveKeyNonString(t *testing.T) {
	r := New()

	input := map[string]any{
		"secret": 12345, // Non-string sensitive value
	}
	result := r.RedactMap(input)

	assert.Equal(t, RedactedPlaceholder, result["secret"])
}

func TestRedactMap_StringWithPatterns(t *testing.T) {
	r := New()

	input := map[string]any{
		"config": "AWS key is AKIAIOSFODNN7EXAMPLE",
	}
	result := r.RedactMap(input)

	// The AWS key pattern should be redacted
	assert.Contains(t, result["config"], RedactedPlaceholder)
}

func TestRedactMap_NestedMap(t *testing.T) {
	r := New()

	input := map[string]any{
		"outer": map[string]any{
			"secret": "nested-secret-value",
			"normal": "visible",
		},
	}
	result := r.RedactMap(input)

	nested := result["outer"].(map[string]any)
	assert.Contains(t, nested["secret"], "[REDACTED]")
	assert.Equal(t, "visible", nested["normal"])
}

func TestRedactMap_PreservesOtherTypes(t *testing.T) {
	r := New()

	input := map[string]any{
		"number": 42,
		"bool":   true,
		"nil":    nil,
		"slice":  []string{"a", "b"},
	}
	result := r.RedactMap(input)

	assert.Equal(t, 42, result["number"])
	assert.Equal(t, true, result["bool"])
	assert.Nil(t, result["nil"])
	assert.Equal(t, []string{"a", "b"}, result["slice"])
}

func TestIsSensitiveKey(t *testing.T) {
	r := New()

	sensitiveKeys := []string{
		"secret", "SECRET", "my_secret",
		"password", "PASSWORD", "user_password",
		"token", "auth_token", "access_token",
		"api_key", "apikey", "api-key",
		"private_key", "privatekey",
		"credential", "credentials",
		"key", "encryption_key",
	}

	for _, key := range sensitiveKeys {
		t.Run(key, func(t *testing.T) {
			assert.True(t, r.isSensitiveKey(key), "Expected %s to be sensitive", key)
		})
	}

	nonSensitiveKeys := []string{
		"name", "email", "id", "count", "status",
	}

	for _, key := range nonSensitiveKeys {
		t.Run(key, func(t *testing.T) {
			assert.False(t, r.isSensitiveKey(key), "Expected %s to NOT be sensitive", key)
		})
	}
}

func TestDefaultRedactor(t *testing.T) {
	assert.NotNil(t, Default)
	assert.True(t, Default.showPartial)
}

func TestPackageLevelRedact(t *testing.T) {
	result := Redact("my-secret-value-here")

	// Default uses partial display
	assert.NotEqual(t, "", result)
	assert.Contains(t, result, "****")
}

func TestRedactFull(t *testing.T) {
	result := RedactFull("my-secret-value")

	assert.Equal(t, RedactedPlaceholder, result)
}

func TestPackageLevelRedactString(t *testing.T) {
	input := "key: AKIAIOSFODNN7EXAMPLE"
	result := RedactString(input)

	assert.NotEqual(t, input, result)
}

func TestPartialRedact_EdgeCases(t *testing.T) {
	r := New(WithPartialDisplay(4, 4))

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "exactly 9 chars",
			input:    "123456789",
			expected: "1234*6789",
		},
		{
			name:     "10 chars",
			input:    "1234567890",
			expected: "1234**7890",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.Redact(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedactString_MultiplePatterns(t *testing.T) {
	r := New()

	// String with multiple secrets
	input := "AWS: AKIAIOSFODNN7EXAMPLE, GitHub: ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	result := r.RedactString(input)

	// Both should be redacted
	assert.NotContains(t, result, "AKIAIOSFODNN7EXAMPLE")
	assert.NotContains(t, result, "ghp_abcdefghijklmnopqrstuvwxyz1234567890")
}

func TestRedactMap_PartialDisplay(t *testing.T) {
	r := New(WithPartialDisplay(4, 4))

	input := map[string]any{
		"password": "my-long-password-value",
	}
	result := r.RedactMap(input)

	// Should show partial redaction
	value := result["password"].(string)
	assert.Contains(t, value, "my-l")
	assert.Contains(t, value, "alue")
	assert.Contains(t, value, "****")
}
