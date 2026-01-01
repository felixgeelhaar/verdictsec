package cyclonedx

import (
	"context"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
)

func TestNewAdapter(t *testing.T) {
	adapter := NewAdapter()

	assert.NotNil(t, adapter)
	assert.Equal(t, "cyclonedx-gomod", adapter.binaryPath)
}

func TestNewAdapterWithPath(t *testing.T) {
	adapter := NewAdapterWithPath("/custom/path/cyclonedx-gomod")

	assert.NotNil(t, adapter)
	assert.Equal(t, "/custom/path/cyclonedx-gomod", adapter.binaryPath)
}

func TestAdapter_ID(t *testing.T) {
	adapter := NewAdapter()

	assert.Equal(t, ports.EngineCycloneDX, adapter.ID())
}

func TestAdapter_Capabilities(t *testing.T) {
	adapter := NewAdapter()

	caps := adapter.Capabilities()

	assert.Len(t, caps, 1)
	assert.Contains(t, caps, ports.CapabilitySBOM)
}

func TestAdapter_IsAvailable(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/cyclonedx-gomod")
	assert.False(t, adapter.IsAvailable())
}

func TestAdapter_Version_Unknown(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/cyclonedx-gomod")

	version := adapter.Version()

	assert.Equal(t, "unknown", version)
}

func TestAdapter_Run_BinaryNotFound(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/cyclonedx-gomod")
	target := ports.NewTarget("/test/path")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CycloneDX Go Mod not found")
}

func TestAdapter_BuildArgs_Default(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{Enabled: true, Settings: make(map[string]string)}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "mod")
	assert.Contains(t, args, "-json")
}

func TestAdapter_BuildArgs_WithType(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"type": "app"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-type=app")
}

func TestAdapter_BuildArgs_WithTestDeps(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"include_test": "true"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-test")
}

func TestAdapter_BuildArgs_WithStdLib(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"include_std": "true"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-std")
}

func TestAdapter_BuildArgs_WithGomod(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"gomod": "/custom/go.mod"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-mod=/custom/go.mod")
}

func TestAdapter_ImplementsEngineInterface(t *testing.T) {
	var _ ports.Engine = (*Adapter)(nil)
}

func TestAdapter_Run_InvalidPath(t *testing.T) {
	adapter := NewAdapter()
	// Path with null bytes is invalid
	target := ports.NewTarget("/test/path\x00invalid")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)

	// Should fail with path validation error or binary not found
	assert.Error(t, err)
}

func TestAdapter_GenerateSBOM_BinaryNotFound(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/cyclonedx-gomod")
	target := ports.NewTarget("/test/path")
	config := ports.DefaultEngineConfig()

	_, err := adapter.GenerateSBOM(context.Background(), target, config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CycloneDX Go Mod not found")
}

func TestAdapter_Version_Cached(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/cyclonedx-gomod")
	adapter.version = "1.2.3" // Pre-set version

	version := adapter.Version()

	// Should return cached version
	assert.Equal(t, "1.2.3", version)
}

func TestAdapter_BuildArgs_AllOptions(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled: true,
		Settings: map[string]string{
			"type":         "app",
			"include_test": "true",
			"include_std":  "true",
			"gomod":        "/custom/go.mod",
		},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "mod")
	assert.Contains(t, args, "-json")
	assert.Contains(t, args, "-type=app")
	assert.Contains(t, args, "-test")
	assert.Contains(t, args, "-std")
	assert.Contains(t, args, "-mod=/custom/go.mod")
}

func TestAdapter_Info(t *testing.T) {
	adapter := NewAdapter()

	info := adapter.Info()

	assert.Equal(t, ports.EngineCycloneDX, info.ID)
	assert.Equal(t, "CycloneDX Go Mod", info.Name)
	assert.NotEmpty(t, info.Description)
	assert.Contains(t, info.InstallCmd, "github.com/CycloneDX/cyclonedx-gomod")
	assert.Equal(t, "https://github.com/CycloneDX/cyclonedx-gomod", info.Homepage)
	assert.Equal(t, ports.CapabilitySBOM, info.Capability)
}
