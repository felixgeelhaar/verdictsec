package ports

import (
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
)

// Config represents the complete application configuration.
type Config struct {
	Version string
	Policy  policy.Policy
	Engines map[EngineID]EngineConfig
	Output  OutputConfig
}

// OutputConfig configures output format and behavior.
type OutputConfig struct {
	Format    OutputFormat
	Verbosity Verbosity
	Color     bool
}

// OutputFormat specifies the output format.
type OutputFormat string

// Available output formats.
const (
	OutputFormatConsole OutputFormat = "console"
	OutputFormatJSON    OutputFormat = "json"
	OutputFormatSARIF   OutputFormat = "sarif"
)

// Verbosity controls output detail level.
type Verbosity string

// Available verbosity levels.
const (
	VerbosityQuiet   Verbosity = "quiet"
	VerbosityNormal  Verbosity = "normal"
	VerbosityVerbose Verbosity = "verbose"
	VerbosityDebug   Verbosity = "debug"
)

// DefaultConfig returns a default configuration.
func DefaultConfig() Config {
	return Config{
		Version: "1",
		Policy:  policy.DefaultPolicy(),
		Engines: map[EngineID]EngineConfig{
			EngineGosec:       DefaultEngineConfig(),
			EngineGovulncheck: DefaultEngineConfig(),
			EngineGitleaks:    DefaultEngineConfig(),
		},
		Output: OutputConfig{
			Format:    OutputFormatConsole,
			Verbosity: VerbosityNormal,
			Color:     true,
		},
	}
}

// GetEngineConfig returns the config for a specific engine.
// Returns default config if not explicitly configured.
func (c Config) GetEngineConfig(id EngineID) EngineConfig {
	if cfg, exists := c.Engines[id]; exists {
		return cfg
	}
	return DefaultEngineConfig()
}

// IsEngineEnabled checks if an engine is enabled.
func (c Config) IsEngineEnabled(id EngineID) bool {
	cfg := c.GetEngineConfig(id)
	return cfg.Enabled
}

// ConfigRepository defines the interface for loading configuration.
type ConfigRepository interface {
	// Load reads configuration from the default location.
	// Returns default config if no config file exists.
	Load() (Config, error)

	// LoadFrom reads configuration from a specific path.
	LoadFrom(path string) (Config, error)

	// Save writes configuration to the default location.
	Save(config Config) error

	// SaveTo writes configuration to a specific path.
	SaveTo(config Config, path string) error

	// Exists checks if a configuration file exists at the default location.
	Exists() bool

	// DefaultPath returns the default configuration file path.
	DefaultPath() string
}

// ConfigOverrides allows CLI flags to override config file values.
type ConfigOverrides struct {
	PolicyMode      *policy.Mode
	FailOn          *string
	WarnOn          *string
	OutputFormat    *OutputFormat
	Verbosity       *Verbosity
	NoColor         *bool
	DisabledEngines []EngineID
	EnabledEngines  []EngineID
}

// Apply merges overrides into a config.
func (o ConfigOverrides) Apply(cfg Config) Config {
	result := cfg

	if o.OutputFormat != nil {
		result.Output.Format = *o.OutputFormat
	}
	if o.Verbosity != nil {
		result.Output.Verbosity = *o.Verbosity
	}
	if o.NoColor != nil && *o.NoColor {
		result.Output.Color = false
	}

	// Disable specified engines
	for _, id := range o.DisabledEngines {
		if engineCfg, exists := result.Engines[id]; exists {
			engineCfg.Enabled = false
			result.Engines[id] = engineCfg
		}
	}

	// Enable only specified engines (disable all others)
	if len(o.EnabledEngines) > 0 {
		for id := range result.Engines {
			engineCfg := result.Engines[id]
			engineCfg.Enabled = false
			result.Engines[id] = engineCfg
		}
		for _, id := range o.EnabledEngines {
			if engineCfg, exists := result.Engines[id]; exists {
				engineCfg.Enabled = true
				result.Engines[id] = engineCfg
			}
		}
	}

	return result
}
