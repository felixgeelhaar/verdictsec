package syft

import (
	"context"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
)

func TestNewAdapter(t *testing.T) {
	adapter := NewAdapter()

	assert.NotNil(t, adapter)
	assert.Equal(t, "syft", adapter.binaryPath)
}

func TestNewAdapterWithPath(t *testing.T) {
	adapter := NewAdapterWithPath("/custom/path/syft")

	assert.NotNil(t, adapter)
	assert.Equal(t, "/custom/path/syft", adapter.binaryPath)
}

func TestAdapter_ID(t *testing.T) {
	adapter := NewAdapter()

	assert.Equal(t, ports.EngineSyft, adapter.ID())
}

func TestAdapter_Capabilities(t *testing.T) {
	adapter := NewAdapter()

	caps := adapter.Capabilities()

	assert.Len(t, caps, 1)
	assert.Contains(t, caps, ports.CapabilitySBOM)
}

func TestAdapter_IsAvailable(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/syft")
	assert.False(t, adapter.IsAvailable())
}

func TestAdapter_Version_Unknown(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/syft")

	version := adapter.Version()

	assert.Equal(t, "unknown", version)
}

func TestAdapter_Run_BinaryNotFound(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/syft")
	target := ports.NewTarget("/test/path")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Syft not found")
}

func TestAdapter_BuildArgs_Default(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{Enabled: true, Settings: make(map[string]string)}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "dir:.")
	assert.Contains(t, args, "-o")
	assert.Contains(t, args, "json")
	assert.Contains(t, args, "--quiet")
}

func TestAdapter_BuildArgs_WithImageSource(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled: true,
		Settings: map[string]string{
			"source_type": "image",
			"image":       "nginx:latest",
		},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "nginx:latest")
}

func TestAdapter_BuildArgs_WithFileSource(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled: true,
		Settings: map[string]string{
			"source_type": "file",
			"file":        "/path/to/binary",
		},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "file:/path/to/binary")
}

func TestAdapter_BuildArgs_WithExclusions(t *testing.T) {
	adapter := NewAdapter()
	target := ports.Target{
		Path:       "/test/path",
		Exclusions: []string{"vendor", "testdata"},
	}
	config := ports.EngineConfig{Enabled: true, Settings: make(map[string]string)}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "--exclude")
	assert.Contains(t, args, "vendor")
	assert.Contains(t, args, "testdata")
}

func TestAdapter_BuildArgs_WithScope(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"scope": "all-layers"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "--scope")
	assert.Contains(t, args, "all-layers")
}

func TestAdapter_BuildArgs_WithConfig(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"config": "/path/to/.syft.yaml"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "--config")
	assert.Contains(t, args, "/path/to/.syft.yaml")
}

func TestAdapter_BuildArgs_WithOutputFormat(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"output_format": "cyclonedx-json"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "cyclonedx-json")
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

func TestAdapter_Version_Cached(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/syft")
	adapter.version = "0.98.0" // Pre-set version

	version := adapter.Version()

	// Should return cached version
	assert.Equal(t, "0.98.0", version)
}

func TestAdapter_GenerateSBOM_BinaryNotFound(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/syft")
	target := ports.NewTarget("/test/path")
	config := ports.DefaultEngineConfig()

	_, err := adapter.GenerateSBOM(context.Background(), target, config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Syft not found")
}

func TestAdapter_Info(t *testing.T) {
	adapter := NewAdapter()

	info := adapter.Info()

	assert.Equal(t, ports.EngineSyft, info.ID)
	assert.Equal(t, "Syft", info.Name)
	assert.NotEmpty(t, info.Description)
	assert.Contains(t, info.InstallCmd, "github.com/anchore/syft")
	assert.Equal(t, "https://github.com/anchore/syft", info.Homepage)
	assert.Equal(t, ports.CapabilitySBOM, info.Capability)
}

func TestAdapter_BuildArgs_AllOptions(t *testing.T) {
	adapter := NewAdapter()
	target := ports.Target{
		Path:       "/test/path",
		Exclusions: []string{"vendor"},
	}
	config := ports.EngineConfig{
		Enabled: true,
		Settings: map[string]string{
			"scope":         "all-layers",
			"config":        "/path/to/.syft.yaml",
			"output_format": "spdx-json",
		},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "dir:.")
	assert.Contains(t, args, "-o")
	assert.Contains(t, args, "spdx-json")
	assert.Contains(t, args, "--quiet")
	assert.Contains(t, args, "--exclude")
	assert.Contains(t, args, "vendor")
	assert.Contains(t, args, "--scope")
	assert.Contains(t, args, "all-layers")
	assert.Contains(t, args, "--config")
	assert.Contains(t, args, "/path/to/.syft.yaml")
}
