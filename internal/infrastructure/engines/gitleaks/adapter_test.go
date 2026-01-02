package gitleaks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
)

func TestNewAdapter(t *testing.T) {
	adapter := NewAdapter()

	assert.NotNil(t, adapter)
	assert.Equal(t, "gitleaks", adapter.binaryPath)
	assert.NotNil(t, adapter.redactor)
}

func TestNewAdapterWithPath(t *testing.T) {
	adapter := NewAdapterWithPath("/custom/path/gitleaks")

	assert.NotNil(t, adapter)
	assert.Equal(t, "/custom/path/gitleaks", adapter.binaryPath)
}

func TestAdapter_ID(t *testing.T) {
	adapter := NewAdapter()

	assert.Equal(t, ports.EngineGitleaks, adapter.ID())
}

func TestAdapter_Capabilities(t *testing.T) {
	adapter := NewAdapter()

	caps := adapter.Capabilities()

	assert.Len(t, caps, 1)
	assert.Contains(t, caps, ports.CapabilitySecrets)
}

func TestAdapter_IsAvailable(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/gitleaks")
	assert.False(t, adapter.IsAvailable())
}

func TestAdapter_Version_Unknown(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/gitleaks")

	version := adapter.Version()

	assert.Equal(t, "unknown", version)
}

func TestAdapter_Run_BinaryNotFound(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/gitleaks")
	target := ports.NewTarget("/test/path")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Gitleaks not found")
}

func TestAdapter_BuildArgs_Default(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{Enabled: true, Settings: make(map[string]string)}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "detect")
	assert.Contains(t, args, "--report-format=json")
	assert.Contains(t, args, "--no-banner")
	assert.Contains(t, args, "--no-git")
	assert.Contains(t, args, "--source=.")
}

func TestAdapter_BuildArgs_GitMode(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"mode": "git"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "--source=.")
	assert.NotContains(t, args, "--no-git")
}

func TestAdapter_BuildArgs_WithExclusions(t *testing.T) {
	adapter := NewAdapter()
	target := ports.Target{
		Path:       "/test/path",
		Exclusions: []string{"vendor", "testdata"},
	}
	config := ports.EngineConfig{Enabled: true, Settings: make(map[string]string)}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "--exclude-path=vendor")
	assert.Contains(t, args, "--exclude-path=testdata")
}

func TestAdapter_BuildArgs_WithConfig(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"config": "/path/to/.gitleaks.toml"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "--config=/path/to/.gitleaks.toml")
}

func TestAdapter_ImplementsEngineInterface(t *testing.T) {
	var _ ports.Engine = (*Adapter)(nil)
}

func TestAdapter_Info(t *testing.T) {
	adapter := NewAdapter()

	info := adapter.Info()

	assert.Equal(t, ports.EngineGitleaks, info.ID)
	assert.Equal(t, "Gitleaks", info.Name)
	assert.NotEmpty(t, info.Description)
	assert.Contains(t, info.InstallCmd, "github.com/gitleaks/gitleaks")
	assert.Equal(t, "https://github.com/gitleaks/gitleaks", info.Homepage)
	assert.Equal(t, ports.CapabilitySecrets, info.Capability)
}

func TestAdapter_BuildEnv_Default(t *testing.T) {
	adapter := NewAdapter()
	config := ports.EngineConfig{Enabled: true, Settings: make(map[string]string)}

	env := adapter.buildEnv(config)

	// Should inherit parent environment
	assert.NotEmpty(t, env)
}

func TestAdapter_BuildEnv_WithLicenseEnv(t *testing.T) {
	adapter := NewAdapter()

	// Set test env var
	testLicense := "test-license-key-12345"
	os.Setenv("TEST_GITLEAKS_LICENSE", testLicense)
	defer os.Unsetenv("TEST_GITLEAKS_LICENSE")

	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"license_env": "TEST_GITLEAKS_LICENSE"},
	}

	env := adapter.buildEnv(config)

	// Find the GITLEAKS_LICENSE entry
	var found bool
	for _, e := range env {
		if strings.HasPrefix(e, "GITLEAKS_LICENSE=") {
			assert.Equal(t, "GITLEAKS_LICENSE="+testLicense, e)
			found = true
			break
		}
	}
	assert.True(t, found, "GITLEAKS_LICENSE should be in environment")
}

func TestAdapter_BuildEnv_WithDirectLicense(t *testing.T) {
	adapter := NewAdapter()

	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"license": "direct-license-key"},
	}

	env := adapter.buildEnv(config)

	// Find the GITLEAKS_LICENSE entry
	var found bool
	for _, e := range env {
		if strings.HasPrefix(e, "GITLEAKS_LICENSE=") {
			assert.Equal(t, "GITLEAKS_LICENSE=direct-license-key", e)
			found = true
			break
		}
	}
	assert.True(t, found, "GITLEAKS_LICENSE should be in environment")
}

func TestAdapter_BuildEnv_LicenseEnvMissing(t *testing.T) {
	adapter := NewAdapter()

	// Reference a non-existent env var
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"license_env": "NONEXISTENT_ENV_VAR"},
	}

	env := adapter.buildEnv(config)

	// GITLEAKS_LICENSE should NOT be added
	for _, e := range env {
		assert.False(t, strings.HasPrefix(e, "GITLEAKS_LICENSE="),
			"GITLEAKS_LICENSE should not be set when env var is missing")
	}
}
