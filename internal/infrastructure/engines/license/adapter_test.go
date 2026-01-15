package license

import (
	"context"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAdapter(t *testing.T) {
	adapter := NewAdapter()
	assert.NotNil(t, adapter)
}

func TestAdapter_ID(t *testing.T) {
	adapter := NewAdapter()
	assert.Equal(t, ports.EngineLicense, adapter.ID())
}

func TestAdapter_Capabilities(t *testing.T) {
	adapter := NewAdapter()
	caps := adapter.Capabilities()

	assert.Len(t, caps, 1)
	assert.Equal(t, ports.CapabilityLicense, caps[0])
}

func TestAdapter_Info(t *testing.T) {
	adapter := NewAdapter()
	info := adapter.Info()

	assert.Equal(t, ports.EngineLicense, info.ID)
	assert.Equal(t, "go-licenses", info.Name)
	assert.Contains(t, info.Description, "license")
	assert.Contains(t, info.InstallCmd, "go-licenses")
	assert.Contains(t, info.Homepage, "github.com")
	assert.Equal(t, ports.CapabilityLicense, info.Capability)
}

func TestAdapter_IsAvailable(t *testing.T) {
	adapter := NewAdapter()
	// This test depends on whether go-licenses is installed
	// We just verify the method doesn't panic
	_ = adapter.IsAvailable()
}

func TestAdapter_Version(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("go-licenses not available")
	}

	version := adapter.Version()
	assert.NotEmpty(t, version)
}

func TestAdapter_Version_Caching(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("go-licenses not available")
	}

	// First call
	version1 := adapter.Version()
	// Second call should return cached value
	version2 := adapter.Version()

	assert.Equal(t, version1, version2)
}

func TestAdapter_Run_InvalidPath(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("go-licenses not available")
	}

	target := ports.NewTarget("../../../../../../../invalid")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestAdapter_Run_ContextCancellation(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("go-licenses not available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	target := ports.NewTarget(".")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(ctx, target, config)
	// Should fail due to cancelled context
	require.Error(t, err)
}

func TestClassifyLicense(t *testing.T) {
	tests := []struct {
		name       string
		license    string
		forbidden  []string
		restricted []string
		allowed    []string
		expected   string
	}{
		{
			name:     "AGPL forbidden by default",
			license:  "AGPL-3.0",
			expected: "CRITICAL",
		},
		{
			name:     "GPL restricted by default",
			license:  "GPL-3.0",
			expected: "HIGH",
		},
		{
			name:     "unknown license",
			license:  "UNKNOWN",
			expected: "MEDIUM",
		},
		{
			name:     "MIT is permissive",
			license:  "MIT",
			expected: "",
		},
		{
			name:     "Apache is permissive",
			license:  "Apache-2.0",
			expected: "",
		},
		{
			name:      "custom forbidden",
			license:   "CUSTOM-BAD",
			forbidden: []string{"CUSTOM-BAD"},
			expected:  "CRITICAL",
		},
		{
			name:       "custom restricted",
			license:    "CUSTOM-RESTRICTED",
			restricted: []string{"CUSTOM-RESTRICTED"},
			expected:   "HIGH",
		},
		{
			name:     "allowed list - in list",
			license:  "MIT",
			allowed:  []string{"MIT", "Apache-2.0"},
			expected: "",
		},
		{
			name:     "allowed list - not in list",
			license:  "BSD-3-Clause",
			allowed:  []string{"MIT", "Apache-2.0"},
			expected: "LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyLicense(tt.license, tt.forbidden, tt.restricted, tt.allowed)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeLicenseID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"MIT", "mit"},
		{"Apache 2.0", "apache-2-0"},
		{"GPL-3.0", "gpl-3-0"},
		{"BSD 3 Clause", "bsd-3-clause"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeLicenseID(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]string
		key      string
		expected []string
	}{
		{
			name:     "missing key",
			settings: map[string]string{},
			key:      "forbidden",
			expected: nil,
		},
		{
			name:     "empty value",
			settings: map[string]string{"forbidden": ""},
			key:      "forbidden",
			expected: nil,
		},
		{
			name:     "JSON array",
			settings: map[string]string{"forbidden": `["AGPL","GPL"]`},
			key:      "forbidden",
			expected: []string{"AGPL", "GPL"},
		},
		{
			name:     "comma separated",
			settings: map[string]string{"forbidden": "AGPL, GPL, SSPL"},
			key:      "forbidden",
			expected: []string{"AGPL", "GPL", "SSPL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringSlice(tt.settings, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Verify interface implementation
func TestAdapter_ImplementsEngineInterface(t *testing.T) {
	var _ ports.Engine = (*Adapter)(nil)
}
