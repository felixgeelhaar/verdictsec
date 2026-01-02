package govulncheck

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

func TestAdapter_BuildEnv_Default(t *testing.T) {
	adapter := NewAdapter()
	config := ports.EngineConfig{Enabled: true, Settings: make(map[string]string)}

	env := adapter.buildEnv(config)

	// Should inherit parent environment
	assert.NotEmpty(t, env)
}

func TestAdapter_BuildEnv_WithGoprivateEnv(t *testing.T) {
	adapter := NewAdapter()

	// Set test env var
	testGoprivate := "github.com/mycompany/*"
	os.Setenv("TEST_GOPRIVATE", testGoprivate)
	defer os.Unsetenv("TEST_GOPRIVATE")

	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"goprivate_env": "TEST_GOPRIVATE"},
	}

	env := adapter.buildEnv(config)

	// Find the GOPRIVATE entry
	var found bool
	for _, e := range env {
		if strings.HasPrefix(e, "GOPRIVATE=") {
			assert.Equal(t, "GOPRIVATE="+testGoprivate, e)
			found = true
			break
		}
	}
	assert.True(t, found, "GOPRIVATE should be in environment")
}

func TestAdapter_BuildEnv_WithDirectGoprivate(t *testing.T) {
	adapter := NewAdapter()

	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"goprivate": "github.com/myorg/*"},
	}

	env := adapter.buildEnv(config)

	// Find the GOPRIVATE entry
	var found bool
	for _, e := range env {
		if strings.HasPrefix(e, "GOPRIVATE=") {
			assert.Equal(t, "GOPRIVATE=github.com/myorg/*", e)
			found = true
			break
		}
	}
	assert.True(t, found, "GOPRIVATE should be in environment")
}

func TestAdapter_BuildEnv_GoprivateEnvMissing(t *testing.T) {
	adapter := NewAdapter()

	// Reference a non-existent env var
	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"goprivate_env": "NONEXISTENT_ENV_VAR"},
	}

	env := adapter.buildEnv(config)

	// GOPRIVATE should NOT be added
	for _, e := range env {
		assert.False(t, strings.HasPrefix(e, "GOPRIVATE="),
			"GOPRIVATE should not be set when env var is missing")
	}
}

func TestAdapter_BuildEnv_WithGonoproxyEnv(t *testing.T) {
	adapter := NewAdapter()

	// Set test env var
	testGonoproxy := "github.com/mycompany/*"
	os.Setenv("TEST_GONOPROXY", testGonoproxy)
	defer os.Unsetenv("TEST_GONOPROXY")

	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"gonoproxy_env": "TEST_GONOPROXY"},
	}

	env := adapter.buildEnv(config)

	// Find the GONOPROXY entry
	var found bool
	for _, e := range env {
		if strings.HasPrefix(e, "GONOPROXY=") {
			assert.Equal(t, "GONOPROXY="+testGonoproxy, e)
			found = true
			break
		}
	}
	assert.True(t, found, "GONOPROXY should be in environment")
}

func TestAdapter_BuildEnv_WithGonosumdbEnv(t *testing.T) {
	adapter := NewAdapter()

	// Set test env var
	testGonosumdb := "github.com/mycompany/*"
	os.Setenv("TEST_GONOSUMDB", testGonosumdb)
	defer os.Unsetenv("TEST_GONOSUMDB")

	config := ports.EngineConfig{
		Enabled:  true,
		Settings: map[string]string{"gonosumdb_env": "TEST_GONOSUMDB"},
	}

	env := adapter.buildEnv(config)

	// Find the GONOSUMDB entry
	var found bool
	for _, e := range env {
		if strings.HasPrefix(e, "GONOSUMDB=") {
			assert.Equal(t, "GONOSUMDB="+testGonosumdb, e)
			found = true
			break
		}
	}
	assert.True(t, found, "GONOSUMDB should be in environment")
}

func TestAdapter_BuildEnv_AllPrivateModuleSettings(t *testing.T) {
	adapter := NewAdapter()

	// Set test env vars
	os.Setenv("MY_GOPRIVATE", "github.com/company/*")
	os.Setenv("MY_GONOPROXY", "github.com/company/*")
	os.Setenv("MY_GONOSUMDB", "github.com/company/*")
	defer os.Unsetenv("MY_GOPRIVATE")
	defer os.Unsetenv("MY_GONOPROXY")
	defer os.Unsetenv("MY_GONOSUMDB")

	config := ports.EngineConfig{
		Enabled: true,
		Settings: map[string]string{
			"goprivate_env": "MY_GOPRIVATE",
			"gonoproxy_env": "MY_GONOPROXY",
			"gonosumdb_env": "MY_GONOSUMDB",
		},
	}

	env := adapter.buildEnv(config)

	// Count how many private module vars were set
	var foundGoprivate, foundGonoproxy, foundGonosumdb bool
	for _, e := range env {
		if strings.HasPrefix(e, "GOPRIVATE=") {
			foundGoprivate = true
		}
		if strings.HasPrefix(e, "GONOPROXY=") {
			foundGonoproxy = true
		}
		if strings.HasPrefix(e, "GONOSUMDB=") {
			foundGonosumdb = true
		}
	}

	assert.True(t, foundGoprivate, "GOPRIVATE should be in environment")
	assert.True(t, foundGonoproxy, "GONOPROXY should be in environment")
	assert.True(t, foundGonosumdb, "GONOSUMDB should be in environment")
}
