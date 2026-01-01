package config

import (
	"fmt"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
)

// Config represents the complete VerdictSec configuration.
type Config struct {
	Version  string         `yaml:"version" json:"version"`
	Policy   PolicyConfig   `yaml:"policy" json:"policy"`
	Engines  EnginesConfig  `yaml:"engines" json:"engines"`
	Output   OutputConfig   `yaml:"output" json:"output"`
	Baseline BaselineConfig `yaml:"baseline" json:"baseline"`
}

// PolicyConfig defines policy settings for scan results.
type PolicyConfig struct {
	Threshold    ThresholdConfig     `yaml:"threshold" json:"threshold"`
	BaselineMode string              `yaml:"baseline_mode" json:"baseline_mode"` // strict, warn, off
	Suppressions []SuppressionConfig `yaml:"suppressions" json:"suppressions"`
}

// ThresholdConfig defines severity thresholds for pass/fail.
type ThresholdConfig struct {
	FailOn string `yaml:"fail_on" json:"fail_on"` // CRITICAL, HIGH, MEDIUM, LOW
	WarnOn string `yaml:"warn_on" json:"warn_on"` // CRITICAL, HIGH, MEDIUM, LOW
}

// SuppressionConfig defines a suppression rule.
type SuppressionConfig struct {
	Fingerprint string    `yaml:"fingerprint" json:"fingerprint"`
	Reason      string    `yaml:"reason" json:"reason"`
	Owner       string    `yaml:"owner" json:"owner"`
	ExpiresAt   time.Time `yaml:"expires_at" json:"expires_at"`
}

// EnginesConfig holds configuration for all engines.
type EnginesConfig struct {
	Gosec       EngineSettings `yaml:"gosec" json:"gosec"`
	Govulncheck EngineSettings `yaml:"govulncheck" json:"govulncheck"`
	Gitleaks    EngineSettings `yaml:"gitleaks" json:"gitleaks"`
	CycloneDX   EngineSettings `yaml:"cyclonedx-gomod" json:"cyclonedx-gomod"`
	Syft        EngineSettings `yaml:"syft" json:"syft"`
}

// EngineSettings holds settings for a single engine.
type EngineSettings struct {
	Enabled         bool              `yaml:"enabled" json:"enabled"`
	Severity        string            `yaml:"severity" json:"severity"`                   // Minimum severity
	Exclude         []string          `yaml:"exclude" json:"exclude"`                     // Rule IDs to exclude
	Settings        map[string]string `yaml:"settings" json:"settings"`                   // Engine-specific settings
	SeverityMapping map[string]string `yaml:"severity_mapping" json:"severity_mapping"`   // Rule ID -> severity overrides
}

// OutputConfig defines output settings.
type OutputConfig struct {
	Format    string `yaml:"format" json:"format"`       // console, json, sarif
	Verbosity string `yaml:"verbosity" json:"verbosity"` // quiet, normal, verbose
	Color     bool   `yaml:"color" json:"color"`
}

// BaselineConfig defines baseline settings.
type BaselineConfig struct {
	Path   string `yaml:"path" json:"path"`
	Strict bool   `yaml:"strict" json:"strict"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Version: "1",
		Policy: PolicyConfig{
			Threshold: ThresholdConfig{
				FailOn: "HIGH",
				WarnOn: "MEDIUM",
			},
			BaselineMode: "warn",
			Suppressions: []SuppressionConfig{},
		},
		Engines: EnginesConfig{
			Gosec: EngineSettings{
				Enabled:  true,
				Severity: "LOW",
				Exclude:  []string{},
				Settings: map[string]string{},
			},
			Govulncheck: EngineSettings{
				Enabled:  true,
				Severity: "LOW",
				Exclude:  []string{},
				Settings: map[string]string{},
			},
			Gitleaks: EngineSettings{
				Enabled:  true,
				Severity: "LOW",
				Exclude:  []string{},
				Settings: map[string]string{
					"redact": "true",
				},
			},
			CycloneDX: EngineSettings{
				Enabled:  true,
				Severity: "LOW",
				Exclude:  []string{},
				Settings: map[string]string{},
			},
			Syft: EngineSettings{
				Enabled:  true,
				Severity: "LOW",
				Exclude:  []string{},
				Settings: map[string]string{},
			},
		},
		Output: OutputConfig{
			Format:    "console",
			Verbosity: "normal",
			Color:     true,
		},
		Baseline: BaselineConfig{
			Path:   ".verdict/baseline.json",
			Strict: false,
		},
	}
}

// ToPortsConfig converts Config to ports.Config for use in use cases.
func (c *Config) ToPortsConfig() ports.Config {
	return ports.Config{
		Version: c.Version,
		Policy:  c.ToDomainPolicy(),
		Engines: map[ports.EngineID]ports.EngineConfig{
			ports.EngineGosec:       c.toEngineConfig(c.Engines.Gosec),
			ports.EngineGovulncheck: c.toEngineConfig(c.Engines.Govulncheck),
			ports.EngineGitleaks:    c.toEngineConfig(c.Engines.Gitleaks),
			ports.EngineCycloneDX:   c.toEngineConfig(c.Engines.CycloneDX),
			ports.EngineSyft:        c.toEngineConfig(c.Engines.Syft),
		},
		Output: ports.OutputConfig{
			Format:    c.GetOutputFormat(),
			Verbosity: c.GetVerbosity(),
			Color:     c.Output.Color,
		},
	}
}

// toEngineConfig converts EngineSettings to ports.EngineConfig.
func (c *Config) toEngineConfig(settings EngineSettings) ports.EngineConfig {
	// Convert severity mapping strings to finding.Severity
	var severityMapping map[string]finding.Severity
	if len(settings.SeverityMapping) > 0 {
		severityMapping = make(map[string]finding.Severity, len(settings.SeverityMapping))
		for ruleID, severity := range settings.SeverityMapping {
			severityMapping[ruleID] = parseSeverity(severity)
		}
	}

	return ports.EngineConfig{
		Enabled:         settings.Enabled,
		MinSeverity:     parseSeverity(settings.Severity),
		ExcludeIDs:      settings.Exclude,
		Settings:        settings.Settings,
		SeverityMapping: severityMapping,
	}
}

// parseSeverity converts a severity string to finding.Severity.
func parseSeverity(s string) finding.Severity {
	switch s {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityLow
	}
}

// GetFailSeverity returns the severity threshold for failure.
func (c *Config) GetFailSeverity() finding.Severity {
	return parseSeverity(c.Policy.Threshold.FailOn)
}

// GetWarnSeverity returns the severity threshold for warnings.
func (c *Config) GetWarnSeverity() finding.Severity {
	return parseSeverity(c.Policy.Threshold.WarnOn)
}

// ToDomainPolicy converts config policy to domain policy.
func (c *Config) ToDomainPolicy() policy.Policy {
	pol := policy.DefaultPolicy()

	// Set thresholds
	pol.Threshold.FailOn = c.GetFailSeverity()
	pol.Threshold.WarnOn = c.GetWarnSeverity()

	// Set baseline mode
	switch c.Policy.BaselineMode {
	case "strict":
		pol.BaselineMode = policy.BaselineModeStrict
	case "warn":
		pol.BaselineMode = policy.BaselineModeWarn
	case "off":
		pol.BaselineMode = policy.BaselineModeOff
	default:
		pol.BaselineMode = policy.BaselineModeWarn
	}

	// Convert suppressions
	for _, s := range c.Policy.Suppressions {
		pol.Suppressions = append(pol.Suppressions, policy.Suppression{
			Fingerprint: s.Fingerprint,
			Reason:      s.Reason,
			Owner:       s.Owner,
			ExpiresAt:   s.ExpiresAt,
		})
	}

	return pol
}

// IsBaselineStrict returns true if baseline mode is strict.
func (c *Config) IsBaselineStrict() bool {
	return c.Policy.BaselineMode == "strict"
}

// IsBaselineEnabled returns true if baseline checking is enabled.
func (c *Config) IsBaselineEnabled() bool {
	return c.Policy.BaselineMode != "off"
}

// EngineConfig returns the config for a specific engine.
func (c *Config) EngineConfig(engineID string) ports.EngineConfig {
	switch engineID {
	case "gosec":
		return c.toEngineConfig(c.Engines.Gosec)
	case "govulncheck":
		return c.toEngineConfig(c.Engines.Govulncheck)
	case "gitleaks":
		return c.toEngineConfig(c.Engines.Gitleaks)
	case "cyclonedx-gomod":
		return c.toEngineConfig(c.Engines.CycloneDX)
	case "syft":
		return c.toEngineConfig(c.Engines.Syft)
	default:
		return ports.EngineConfig{Enabled: false}
	}
}

// GetOutputFormat returns the output format as a ports.OutputFormat.
func (c *Config) GetOutputFormat() ports.OutputFormat {
	switch c.Output.Format {
	case "json":
		return ports.OutputFormatJSON
	case "sarif":
		return ports.OutputFormatSARIF
	default:
		return ports.OutputFormatConsole
	}
}

// GetVerbosity returns the verbosity as a ports.Verbosity.
func (c *Config) GetVerbosity() ports.Verbosity {
	switch c.Output.Verbosity {
	case "quiet":
		return ports.VerbosityQuiet
	case "verbose":
		return ports.VerbosityVerbose
	case "debug":
		return ports.VerbosityDebug
	default:
		return ports.VerbosityNormal
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() []error {
	var errs []error

	// Validate version
	if c.Version == "" {
		errs = append(errs, &ValidationError{Field: "version", Message: "version is required"})
	}

	// Validate policy thresholds
	validSeverities := map[string]bool{
		"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true,
	}

	if c.Policy.Threshold.FailOn != "" && !validSeverities[c.Policy.Threshold.FailOn] {
		errs = append(errs, &ValidationError{
			Field:   "policy.threshold.fail_on",
			Message: "must be one of: CRITICAL, HIGH, MEDIUM, LOW",
		})
	}

	if c.Policy.Threshold.WarnOn != "" && !validSeverities[c.Policy.Threshold.WarnOn] {
		errs = append(errs, &ValidationError{
			Field:   "policy.threshold.warn_on",
			Message: "must be one of: CRITICAL, HIGH, MEDIUM, LOW",
		})
	}

	// Validate baseline mode
	validModes := map[string]bool{"strict": true, "warn": true, "off": true}
	if c.Policy.BaselineMode != "" && !validModes[c.Policy.BaselineMode] {
		errs = append(errs, &ValidationError{
			Field:   "policy.baseline_mode",
			Message: "must be one of: strict, warn, off",
		})
	}

	// Validate suppressions
	for i, supp := range c.Policy.Suppressions {
		if supp.Fingerprint == "" {
			errs = append(errs, &ValidationError{
				Field:   fmt.Sprintf("policy.suppressions[%d].fingerprint", i),
				Message: "fingerprint is required",
			})
		}
		if supp.Reason == "" {
			errs = append(errs, &ValidationError{
				Field:   fmt.Sprintf("policy.suppressions[%d].reason", i),
				Message: "reason is required",
			})
		}
		if supp.Owner == "" {
			errs = append(errs, &ValidationError{
				Field:   fmt.Sprintf("policy.suppressions[%d].owner", i),
				Message: "owner is required",
			})
		}
	}

	// Validate output format
	validFormats := map[string]bool{"console": true, "json": true, "sarif": true}
	if c.Output.Format != "" && !validFormats[c.Output.Format] {
		errs = append(errs, &ValidationError{
			Field:   "output.format",
			Message: "must be one of: console, json, sarif",
		})
	}

	// Validate verbosity
	validVerbosity := map[string]bool{"quiet": true, "normal": true, "verbose": true}
	if c.Output.Verbosity != "" && !validVerbosity[c.Output.Verbosity] {
		errs = append(errs, &ValidationError{
			Field:   "output.verbosity",
			Message: "must be one of: quiet, normal, verbose",
		})
	}

	return errs
}

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Message
}
