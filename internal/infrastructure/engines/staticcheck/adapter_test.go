package staticcheck

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
	assert.Equal(t, "staticcheck", adapter.binaryPath)
}

func TestNewAdapterWithPath(t *testing.T) {
	adapter := NewAdapterWithPath("/custom/path/staticcheck")
	assert.NotNil(t, adapter)
	assert.Equal(t, "/custom/path/staticcheck", adapter.binaryPath)
}

func TestAdapter_ID(t *testing.T) {
	adapter := NewAdapter()
	assert.Equal(t, ports.EngineStaticcheck, adapter.ID())
}

func TestAdapter_Capabilities(t *testing.T) {
	adapter := NewAdapter()
	caps := adapter.Capabilities()

	assert.Len(t, caps, 1)
	assert.Equal(t, ports.CapabilitySAST, caps[0])
}

func TestAdapter_Info(t *testing.T) {
	adapter := NewAdapter()
	info := adapter.Info()

	assert.Equal(t, ports.EngineStaticcheck, info.ID)
	assert.Equal(t, "Staticcheck", info.Name)
	assert.Contains(t, info.Description, "Dead code")
	assert.Contains(t, info.InstallCmd, "honnef.co/go/tools")
	assert.Equal(t, "https://staticcheck.dev/", info.Homepage)
	assert.Equal(t, ports.CapabilitySAST, info.Capability)
}

func TestAdapter_IsAvailable(t *testing.T) {
	adapter := NewAdapter()
	// This test depends on whether staticcheck is installed
	// We just verify the method doesn't panic
	_ = adapter.IsAvailable()
}

func TestAdapter_Version(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("staticcheck not available")
	}

	version := adapter.Version()
	assert.NotEmpty(t, version)
	assert.NotEqual(t, "unknown", version)
}

func TestAdapter_Version_Caching(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("staticcheck not available")
	}

	// First call
	version1 := adapter.Version()
	// Second call should return cached value
	version2 := adapter.Version()

	assert.Equal(t, version1, version2)
}

func TestAdapter_BuildArgs(t *testing.T) {
	adapter := NewAdapter()

	target := ports.Target{
		Path:       "/test/path",
		Exclusions: []string{"vendor/"},
	}

	config := ports.EngineConfig{
		Enabled: true,
	}

	args := adapter.buildArgs(target, config)

	// Should include JSON format
	assert.Contains(t, args, "-f")
	assert.Contains(t, args, "json")

	// Should include checks flag
	assert.Contains(t, args, "-checks")
	assert.Contains(t, args, "U1000")

	// Should include recursive scan
	assert.Contains(t, args, "./...")
}

func TestAdapter_Run_BinaryNotFound(t *testing.T) {
	adapter := NewAdapterWithPath("/nonexistent/staticcheck")

	target := ports.NewTarget("/test/path")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAdapter_Run_InvalidPath(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("staticcheck not available")
	}

	// Create target with non-existent path
	target := ports.NewTarget("/nonexistent/path/to/project")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(context.Background(), target, config)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")
}

func TestAdapter_Run_ContextCancellation(t *testing.T) {
	adapter := NewAdapter()
	if !adapter.IsAvailable() {
		t.Skip("staticcheck not available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	target := ports.NewTarget(".")
	config := ports.DefaultEngineConfig()

	_, _, err := adapter.Run(ctx, target, config)

	// Should fail due to cancelled context
	require.Error(t, err)
}

// Verify interface implementation
func TestAdapter_ImplementsEngineInterface(t *testing.T) {
	var _ ports.Engine = (*Adapter)(nil)
}
