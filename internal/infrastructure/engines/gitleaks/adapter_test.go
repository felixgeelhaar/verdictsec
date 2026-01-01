package gitleaks

import (
	"context"
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
	assert.Contains(t, err.Error(), "gitleaks binary not found")
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
