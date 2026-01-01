package ports

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "1", cfg.Version)
	assert.NotNil(t, cfg.Engines)
	assert.True(t, cfg.IsEngineEnabled(EngineGosec))
	assert.True(t, cfg.IsEngineEnabled(EngineGovulncheck))
	assert.True(t, cfg.IsEngineEnabled(EngineGitleaks))
}

func TestConfig_GetEngineConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Existing engine
	gosecCfg := cfg.GetEngineConfig(EngineGosec)
	assert.True(t, gosecCfg.Enabled)

	// Non-existing engine returns default
	unknownCfg := cfg.GetEngineConfig("unknown")
	assert.True(t, unknownCfg.Enabled)
	assert.Equal(t, finding.SeverityLow, unknownCfg.MinSeverity)
}

func TestConfig_IsEngineEnabled(t *testing.T) {
	cfg := DefaultConfig()

	// Enabled by default
	assert.True(t, cfg.IsEngineEnabled(EngineGosec))

	// Disable an engine
	gosecCfg := cfg.Engines[EngineGosec]
	gosecCfg.Enabled = false
	cfg.Engines[EngineGosec] = gosecCfg

	assert.False(t, cfg.IsEngineEnabled(EngineGosec))
}

func TestOutputFormat_Constants(t *testing.T) {
	assert.Equal(t, OutputFormat("console"), OutputFormatConsole)
	assert.Equal(t, OutputFormat("json"), OutputFormatJSON)
	assert.Equal(t, OutputFormat("sarif"), OutputFormatSARIF)
	assert.Equal(t, OutputFormat("github"), OutputFormatGitHubActions)
	assert.Equal(t, OutputFormat("html"), OutputFormatHTML)
}

func TestVerbosity_Constants(t *testing.T) {
	assert.Equal(t, Verbosity("quiet"), VerbosityQuiet)
	assert.Equal(t, Verbosity("normal"), VerbosityNormal)
	assert.Equal(t, Verbosity("verbose"), VerbosityVerbose)
	assert.Equal(t, Verbosity("debug"), VerbosityDebug)
}

func TestConfigOverrides_Apply(t *testing.T) {
	cfg := DefaultConfig()
	jsonFormat := OutputFormatJSON
	verboseLevel := VerbosityVerbose
	noColor := true

	overrides := ConfigOverrides{
		OutputFormat: &jsonFormat,
		Verbosity:    &verboseLevel,
		NoColor:      &noColor,
	}

	result := overrides.Apply(cfg)

	assert.Equal(t, OutputFormatJSON, result.Output.Format)
	assert.Equal(t, VerbosityVerbose, result.Output.Verbosity)
	assert.False(t, result.Output.Color)
}

func TestConfigOverrides_Apply_DisableEngines(t *testing.T) {
	cfg := DefaultConfig()

	overrides := ConfigOverrides{
		DisabledEngines: []EngineID{EngineGosec},
	}

	result := overrides.Apply(cfg)

	assert.False(t, result.IsEngineEnabled(EngineGosec))
	assert.True(t, result.IsEngineEnabled(EngineGovulncheck))
}

func TestConfigOverrides_Apply_EnableOnlyEngines(t *testing.T) {
	cfg := DefaultConfig()

	overrides := ConfigOverrides{
		EnabledEngines: []EngineID{EngineGosec},
	}

	result := overrides.Apply(cfg)

	assert.True(t, result.IsEngineEnabled(EngineGosec))
	assert.False(t, result.IsEngineEnabled(EngineGovulncheck))
	assert.False(t, result.IsEngineEnabled(EngineGitleaks))
}

func TestConfigOverrides_Apply_NoOverrides(t *testing.T) {
	cfg := DefaultConfig()
	overrides := ConfigOverrides{}

	result := overrides.Apply(cfg)

	assert.Equal(t, cfg.Output.Format, result.Output.Format)
	assert.Equal(t, cfg.Output.Verbosity, result.Output.Verbosity)
	assert.Equal(t, cfg.Output.Color, result.Output.Color)
}
