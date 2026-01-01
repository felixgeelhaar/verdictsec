package govulncheck

import (
	"context"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
)

func TestNewAdapter(t *testing.T) {
	adapter := NewAdapter()

	assert.NotNil(t, adapter)
	assert.Equal(t, "govulncheck", adapter.binaryPath)
}

func TestNewAdapterWithPath(t *testing.T) {
	adapter := NewAdapterWithPath("/custom/path/govulncheck")

	assert.NotNil(t, adapter)
	assert.Equal(t, "/custom/path/govulncheck", adapter.binaryPath)
}

func TestAdapter_ID(t *testing.T) {
	adapter := NewAdapter()

	assert.Equal(t, ports.EngineGovulncheck, adapter.ID())
}

func TestAdapter_Capabilities(t *testing.T) {
	adapter := NewAdapter()

	caps := adapter.Capabilities()

	assert.Len(t, caps, 1)
	assert.Contains(t, caps, ports.CapabilityVuln)
}

func TestAdapter_IsAvailable(t *testing.T) {
	// Test with invalid path - should not be available
	adapter := NewAdapterWithPath("/nonexistent/govulncheck")
	assert.False(t, adapter.IsAvailable())
}

func TestAdapter_Version_Unknown(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/govulncheck")

	version := adapter.Version()

	assert.Equal(t, "unknown", version)
}

func TestAdapter_Run_BinaryNotFound(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/govulncheck")
	target := ports.NewTarget("/test/path")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Govulncheck not found")
}

func TestAdapter_BuildArgs_Default(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{Enabled: true, Settings: make(map[string]string)}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-format=json")
	assert.Contains(t, args, "./...")
}

func TestAdapter_BuildArgs_WithMode(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"mode": "binary"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-mode=binary")
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

	assert.Error(t, err)
}

func TestAdapter_Version_Cached(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/govulncheck")
	adapter.version = "v1.0.0"

	version := adapter.Version()

	assert.Equal(t, "v1.0.0", version)
}

func TestAdapter_BuildArgs_SourceMode(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"mode": "source"},
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-mode=source")
}

func TestAdapter_BuildArgs_EmptySettings(t *testing.T) {
	adapter := NewAdapter()
	target := ports.NewTarget("/test/path")
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: make(map[string]string),
	}

	args := adapter.buildArgs(target, config)

	assert.Contains(t, args, "-format=json")
	assert.Contains(t, args, "./...")
	// Without mode setting, only basic args
	assert.Len(t, args, 2)
}

func TestAdapter_Info(t *testing.T) {
	adapter := NewAdapter()

	info := adapter.Info()

	assert.Equal(t, ports.EngineGovulncheck, info.ID)
	assert.Equal(t, "Govulncheck", info.Name)
	assert.NotEmpty(t, info.Description)
	assert.Contains(t, info.InstallCmd, "golang.org/x/vuln/cmd/govulncheck")
	assert.Equal(t, "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck", info.Homepage)
	assert.Equal(t, ports.CapabilityVuln, info.Capability)
}
