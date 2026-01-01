package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigDir is the default directory for verdict config.
	DefaultConfigDir = ".verdict"

	// DefaultConfigFile is the default config file name.
	DefaultConfigFile = "config.yaml"
)

// Loader handles loading and merging configuration.
type Loader struct {
	configPaths []string
}

// NewLoader creates a new config loader.
func NewLoader() *Loader {
	return &Loader{
		configPaths: []string{
			filepath.Join(DefaultConfigDir, DefaultConfigFile),
			"verdict.yaml",
			".verdict.yaml",
		},
	}
}

// NewLoaderWithPaths creates a loader with custom config paths.
func NewLoaderWithPaths(paths []string) *Loader {
	return &Loader{
		configPaths: paths,
	}
}

// Load loads configuration from the first available config file.
// Returns default config if no file is found.
func (l *Loader) Load() (*Config, error) {
	for _, path := range l.configPaths {
		if fileExists(path) {
			return l.LoadFromFile(path)
		}
	}

	// No config file found, return defaults
	return DefaultConfig(), nil
}

// LoadFromFile loads configuration from a specific file.
func (l *Loader) LoadFromFile(path string) (*Config, error) {
	// Validate path to prevent path traversal attacks
	cleanPath, err := pathutil.ValidatePath(path)
	if err != nil {
		return nil, fmt.Errorf("invalid config path: %w", err)
	}

	data, err := os.ReadFile(cleanPath) // #nosec G304 - path is validated above
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", cleanPath, err)
	}

	return l.LoadFromBytes(data)
}

// LoadFromBytes loads configuration from YAML bytes.
func (l *Loader) LoadFromBytes(data []byte) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// Unmarshal YAML into config
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate config
	if errs := cfg.Validate(); len(errs) > 0 {
		return nil, &ConfigErrors{Errors: errs}
	}

	return cfg, nil
}

// LoadWithOverrides loads config and applies CLI overrides.
func (l *Loader) LoadWithOverrides(overrides *CLIOverrides) (*Config, error) {
	cfg, err := l.Load()
	if err != nil {
		return nil, err
	}

	// Apply overrides
	if overrides != nil {
		cfg = applyOverrides(cfg, overrides)
	}

	return cfg, nil
}

// LoadFromFileWithOverrides loads from a specific file and applies overrides.
func (l *Loader) LoadFromFileWithOverrides(path string, overrides *CLIOverrides) (*Config, error) {
	cfg, err := l.LoadFromFile(path)
	if err != nil {
		return nil, err
	}

	// Apply overrides
	if overrides != nil {
		cfg = applyOverrides(cfg, overrides)
	}

	return cfg, nil
}

// CLIOverrides represents command-line configuration overrides.
type CLIOverrides struct {
	// Output settings
	Format    *string
	Verbosity *string
	NoColor   *bool

	// Policy settings
	FailOn       *string
	BaselineMode *string

	// Engine toggles
	DisableEngines []string
	EnableEngines  []string

	// Baseline
	BaselinePath *string
}

// applyOverrides applies CLI overrides to a config.
func applyOverrides(cfg *Config, overrides *CLIOverrides) *Config {
	// Output overrides
	if overrides.Format != nil {
		cfg.Output.Format = *overrides.Format
	}
	if overrides.Verbosity != nil {
		cfg.Output.Verbosity = *overrides.Verbosity
	}
	if overrides.NoColor != nil {
		cfg.Output.Color = !*overrides.NoColor
	}

	// Policy overrides
	if overrides.FailOn != nil {
		cfg.Policy.Threshold.FailOn = *overrides.FailOn
	}
	if overrides.BaselineMode != nil {
		cfg.Policy.BaselineMode = *overrides.BaselineMode
	}

	// Engine toggles
	for _, engine := range overrides.DisableEngines {
		disableEngine(cfg, engine)
	}
	for _, engine := range overrides.EnableEngines {
		enableEngine(cfg, engine)
	}

	// Baseline path
	if overrides.BaselinePath != nil {
		cfg.Baseline.Path = *overrides.BaselinePath
	}

	return cfg
}

// disableEngine disables a specific engine.
func disableEngine(cfg *Config, engine string) {
	switch engine {
	case "gosec":
		cfg.Engines.Gosec.Enabled = false
	case "govulncheck":
		cfg.Engines.Govulncheck.Enabled = false
	case "gitleaks":
		cfg.Engines.Gitleaks.Enabled = false
	case "cyclonedx-gomod", "cyclonedx":
		cfg.Engines.CycloneDX.Enabled = false
	}
}

// enableEngine enables a specific engine.
func enableEngine(cfg *Config, engine string) {
	switch engine {
	case "gosec":
		cfg.Engines.Gosec.Enabled = true
	case "govulncheck":
		cfg.Engines.Govulncheck.Enabled = true
	case "gitleaks":
		cfg.Engines.Gitleaks.Enabled = true
	case "cyclonedx-gomod", "cyclonedx":
		cfg.Engines.CycloneDX.Enabled = true
	}
}

// SaveToFile saves configuration to a file.
func SaveToFile(cfg *Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GenerateDefaultConfig creates a default config file at the given path.
func GenerateDefaultConfig(path string) error {
	return SaveToFile(DefaultConfig(), path)
}

// FindConfigFile finds the first available config file.
func FindConfigFile() (string, bool) {
	loader := NewLoader()
	for _, path := range loader.configPaths {
		if fileExists(path) {
			return path, true
		}
	}
	return "", false
}

// fileExists checks if a file exists.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// ConfigErrors wraps multiple configuration errors.
type ConfigErrors struct {
	Errors []error
}

func (e *ConfigErrors) Error() string {
	if len(e.Errors) == 0 {
		return "no configuration errors"
	}
	if len(e.Errors) == 1 {
		return "configuration error: " + e.Errors[0].Error()
	}
	msg := fmt.Sprintf("%d configuration errors:", len(e.Errors))
	for _, err := range e.Errors {
		msg += "\n  - " + err.Error()
	}
	return msg
}

// Unwrap returns the underlying errors.
func (e *ConfigErrors) Unwrap() []error {
	return e.Errors
}
