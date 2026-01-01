package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoader(t *testing.T) {
	loader := NewLoader()

	assert.NotNil(t, loader)
	assert.NotEmpty(t, loader.configPaths)
}

func TestNewLoaderWithPaths(t *testing.T) {
	paths := []string{"custom.yaml", "other.yaml"}
	loader := NewLoaderWithPaths(paths)

	assert.NotNil(t, loader)
	assert.Equal(t, paths, loader.configPaths)
}

func TestLoader_Load_NoFile(t *testing.T) {
	// Use a temp directory with no config files
	loader := NewLoaderWithPaths([]string{"/nonexistent/config.yaml"})

	cfg, err := loader.Load()

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "1", cfg.Version) // Default config
}

func TestLoader_LoadFromBytes_ValidYAML(t *testing.T) {
	loader := NewLoader()
	yaml := []byte(`
version: "1"
policy:
  threshold:
    fail_on: CRITICAL
    warn_on: HIGH
  baseline_mode: strict
engines:
  gosec:
    enabled: true
    severity: MEDIUM
    exclude:
      - G104
output:
  format: json
  verbosity: verbose
  color: false
`)

	cfg, err := loader.LoadFromBytes(yaml)

	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Version)
	assert.Equal(t, "CRITICAL", cfg.Policy.Threshold.FailOn)
	assert.Equal(t, "strict", cfg.Policy.BaselineMode)
	assert.Equal(t, "MEDIUM", cfg.Engines.Gosec.Severity)
	assert.Contains(t, cfg.Engines.Gosec.Exclude, "G104")
	assert.Equal(t, "json", cfg.Output.Format)
	assert.False(t, cfg.Output.Color)
}

func TestLoader_LoadFromBytes_InvalidYAML(t *testing.T) {
	loader := NewLoader()
	yaml := []byte(`{invalid yaml`)

	_, err := loader.LoadFromBytes(yaml)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config")
}

func TestLoader_LoadFromBytes_InvalidConfig(t *testing.T) {
	loader := NewLoader()
	yaml := []byte(`
version: ""
policy:
  threshold:
    fail_on: INVALID
`)

	_, err := loader.LoadFromBytes(yaml)

	assert.Error(t, err)
}

func TestLoader_LoadFromFile(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	yaml := []byte(`
version: "1"
policy:
  threshold:
    fail_on: HIGH
`)
	require.NoError(t, os.WriteFile(configPath, yaml, 0644))

	loader := NewLoader()
	cfg, err := loader.LoadFromFile(configPath)

	require.NoError(t, err)
	assert.Equal(t, "HIGH", cfg.Policy.Threshold.FailOn)
}

func TestLoader_LoadFromFile_NotFound(t *testing.T) {
	loader := NewLoader()

	_, err := loader.LoadFromFile("/nonexistent/config.yaml")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoader_LoadWithOverrides(t *testing.T) {
	loader := NewLoaderWithPaths([]string{"/nonexistent/config.yaml"})
	format := "json"
	noColor := true
	failOn := "CRITICAL"

	overrides := &CLIOverrides{
		Format:  &format,
		NoColor: &noColor,
		FailOn:  &failOn,
	}

	cfg, err := loader.LoadWithOverrides(overrides)

	require.NoError(t, err)
	assert.Equal(t, "json", cfg.Output.Format)
	assert.False(t, cfg.Output.Color)
	assert.Equal(t, "CRITICAL", cfg.Policy.Threshold.FailOn)
}

func TestLoader_LoadWithOverrides_NilOverrides(t *testing.T) {
	loader := NewLoaderWithPaths([]string{"/nonexistent/config.yaml"})

	cfg, err := loader.LoadWithOverrides(nil)

	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestApplyOverrides_DisableEngines(t *testing.T) {
	cfg := DefaultConfig()
	overrides := &CLIOverrides{
		DisableEngines: []string{"gosec", "gitleaks"},
	}

	result := applyOverrides(cfg, overrides)

	assert.False(t, result.Engines.Gosec.Enabled)
	assert.False(t, result.Engines.Gitleaks.Enabled)
	assert.True(t, result.Engines.Govulncheck.Enabled)
}

func TestApplyOverrides_EnableEngines(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false

	overrides := &CLIOverrides{
		EnableEngines: []string{"gosec", "gitleaks"},
	}

	result := applyOverrides(cfg, overrides)

	assert.True(t, result.Engines.Gosec.Enabled)
	assert.True(t, result.Engines.Gitleaks.Enabled)
}

func TestApplyOverrides_BaselinePath(t *testing.T) {
	cfg := DefaultConfig()
	path := "/custom/baseline.json"
	overrides := &CLIOverrides{
		BaselinePath: &path,
	}

	result := applyOverrides(cfg, overrides)

	assert.Equal(t, "/custom/baseline.json", result.Baseline.Path)
}

func TestApplyOverrides_Verbosity(t *testing.T) {
	cfg := DefaultConfig()
	verbosity := "verbose"
	overrides := &CLIOverrides{
		Verbosity: &verbosity,
	}

	result := applyOverrides(cfg, overrides)

	assert.Equal(t, "verbose", result.Output.Verbosity)
}

func TestApplyOverrides_BaselineMode(t *testing.T) {
	cfg := DefaultConfig()
	mode := "strict"
	overrides := &CLIOverrides{
		BaselineMode: &mode,
	}

	result := applyOverrides(cfg, overrides)

	assert.Equal(t, "strict", result.Policy.BaselineMode)
}

func TestDisableEngine(t *testing.T) {
	tests := []struct {
		engine   string
		checkFn  func(*Config) bool
	}{
		{"gosec", func(c *Config) bool { return !c.Engines.Gosec.Enabled }},
		{"govulncheck", func(c *Config) bool { return !c.Engines.Govulncheck.Enabled }},
		{"gitleaks", func(c *Config) bool { return !c.Engines.Gitleaks.Enabled }},
		{"cyclonedx-gomod", func(c *Config) bool { return !c.Engines.CycloneDX.Enabled }},
		{"cyclonedx", func(c *Config) bool { return !c.Engines.CycloneDX.Enabled }},
	}

	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			cfg := DefaultConfig()
			disableEngine(cfg, tt.engine)
			assert.True(t, tt.checkFn(cfg))
		})
	}
}

func TestEnableEngine(t *testing.T) {
	tests := []struct {
		engine   string
		checkFn  func(*Config) bool
	}{
		{"gosec", func(c *Config) bool { return c.Engines.Gosec.Enabled }},
		{"govulncheck", func(c *Config) bool { return c.Engines.Govulncheck.Enabled }},
		{"gitleaks", func(c *Config) bool { return c.Engines.Gitleaks.Enabled }},
		{"cyclonedx-gomod", func(c *Config) bool { return c.Engines.CycloneDX.Enabled }},
	}

	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			cfg := DefaultConfig()
			// Disable first
			disableEngine(cfg, tt.engine)
			// Then enable
			enableEngine(cfg, tt.engine)
			assert.True(t, tt.checkFn(cfg))
		})
	}
}

func TestSaveToFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "subdir", "config.yaml")
	cfg := DefaultConfig()
	cfg.Policy.Threshold.FailOn = "CRITICAL"

	err := SaveToFile(cfg, configPath)

	require.NoError(t, err)

	// Verify file was created
	loader := NewLoader()
	loaded, err := loader.LoadFromFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, "CRITICAL", loaded.Policy.Threshold.FailOn)
}

func TestGenerateDefaultConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	err := GenerateDefaultConfig(configPath)

	require.NoError(t, err)

	// Verify file was created with defaults
	loader := NewLoader()
	cfg, err := loader.LoadFromFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Version)
	assert.Equal(t, "HIGH", cfg.Policy.Threshold.FailOn)
}

func TestFindConfigFile(t *testing.T) {
	// Test when no config exists
	path, found := FindConfigFile()
	assert.False(t, found)
	assert.Empty(t, path)
}

func TestConfigErrors_Error(t *testing.T) {
	// No errors
	errs := &ConfigErrors{Errors: []error{}}
	assert.Equal(t, "no configuration errors", errs.Error())

	// One error
	errs = &ConfigErrors{Errors: []error{&ValidationError{Field: "test", Message: "error"}}}
	assert.Contains(t, errs.Error(), "configuration error")

	// Multiple errors
	errs = &ConfigErrors{Errors: []error{
		&ValidationError{Field: "test1", Message: "error1"},
		&ValidationError{Field: "test2", Message: "error2"},
	}}
	assert.Contains(t, errs.Error(), "2 configuration errors")
}

func TestConfigErrors_Unwrap(t *testing.T) {
	err1 := &ValidationError{Field: "test1", Message: "error1"}
	err2 := &ValidationError{Field: "test2", Message: "error2"}
	errs := &ConfigErrors{Errors: []error{err1, err2}}

	unwrapped := errs.Unwrap()

	assert.Len(t, unwrapped, 2)
	assert.Equal(t, err1, unwrapped[0])
	assert.Equal(t, err2, unwrapped[1])
}

func TestFileExists(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte("test"), 0644))

	assert.True(t, fileExists(tmpFile))
	assert.False(t, fileExists("/nonexistent/file.txt"))
	assert.False(t, fileExists(tmpDir)) // Directory, not file
}

func TestLoader_LoadFromFileWithOverrides(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	yaml := []byte(`
version: "1"
policy:
  threshold:
    fail_on: MEDIUM
output:
  format: console
`)
	require.NoError(t, os.WriteFile(configPath, yaml, 0644))

	loader := NewLoader()
	format := "json"
	failOn := "CRITICAL"
	overrides := &CLIOverrides{
		Format: &format,
		FailOn: &failOn,
	}

	cfg, err := loader.LoadFromFileWithOverrides(configPath, overrides)

	require.NoError(t, err)
	// Original values overridden
	assert.Equal(t, "json", cfg.Output.Format)
	assert.Equal(t, "CRITICAL", cfg.Policy.Threshold.FailOn)
}

func TestLoader_LoadFromFileWithOverrides_NilOverrides(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	yaml := []byte(`
version: "1"
policy:
  threshold:
    fail_on: HIGH
`)
	require.NoError(t, os.WriteFile(configPath, yaml, 0644))

	loader := NewLoader()

	cfg, err := loader.LoadFromFileWithOverrides(configPath, nil)

	require.NoError(t, err)
	assert.Equal(t, "HIGH", cfg.Policy.Threshold.FailOn)
}

func TestLoader_LoadFromFileWithOverrides_FileNotFound(t *testing.T) {
	loader := NewLoader()

	_, err := loader.LoadFromFileWithOverrides("/nonexistent/config.yaml", nil)

	assert.Error(t, err)
}

func TestLoader_LoadFromFile_InvalidPath(t *testing.T) {
	loader := NewLoader()

	// Path with null bytes should fail validation
	_, err := loader.LoadFromFile("invalid\x00path")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config path")
}

func TestLoader_Load_FirstFileFound(t *testing.T) {
	tmpDir := t.TempDir()

	// Create config file
	configPath := filepath.Join(tmpDir, "first.yaml")
	yaml := []byte(`
version: "1"
policy:
  threshold:
    fail_on: LOW
`)
	require.NoError(t, os.WriteFile(configPath, yaml, 0644))

	loader := NewLoaderWithPaths([]string{configPath, "/other/file.yaml"})

	cfg, err := loader.Load()

	require.NoError(t, err)
	assert.Equal(t, "LOW", cfg.Policy.Threshold.FailOn)
}

func TestDisableEngine_Unknown(t *testing.T) {
	cfg := DefaultConfig()
	originalGosec := cfg.Engines.Gosec.Enabled

	// Unknown engine should not change anything
	disableEngine(cfg, "unknown-engine")

	assert.Equal(t, originalGosec, cfg.Engines.Gosec.Enabled)
}

func TestEnableEngine_Unknown(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Engines.Gosec.Enabled = false

	// Unknown engine should not change anything
	enableEngine(cfg, "unknown-engine")

	assert.False(t, cfg.Engines.Gosec.Enabled)
}
