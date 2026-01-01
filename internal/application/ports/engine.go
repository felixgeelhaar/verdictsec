package ports

import (
	"context"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// EngineID uniquely identifies a security scanner engine.
type EngineID string

// Common engine IDs.
const (
	EngineGosec       EngineID = "gosec"
	EngineGovulncheck EngineID = "govulncheck"
	EngineGitleaks    EngineID = "gitleaks"
	EngineCycloneDX   EngineID = "cyclonedx-gomod"
	EngineSyft        EngineID = "syft"
)

// Capability represents what a scanner can do.
type Capability string

// Available capabilities.
const (
	CapabilitySAST    Capability = "sast"
	CapabilityVuln    Capability = "vuln"
	CapabilitySecrets Capability = "secrets"
	CapabilitySBOM    Capability = "sbom"
)

// Target represents what to scan.
type Target struct {
	Path       string   // Directory or file to scan
	Exclusions []string // Paths to exclude
}

// NewTarget creates a new scan target.
func NewTarget(path string, exclusions ...string) Target {
	return Target{
		Path:       path,
		Exclusions: exclusions,
	}
}

// EngineConfig holds engine-specific configuration.
type EngineConfig struct {
	Enabled         bool
	MinSeverity     finding.Severity
	ExcludeIDs      []string                    // Rule IDs to exclude
	Settings        map[string]string           // Engine-specific settings
	SeverityMapping map[string]finding.Severity // Rule ID -> severity overrides
}

// DefaultEngineConfig returns a default engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Enabled:     true,
		MinSeverity: finding.SeverityLow,
		ExcludeIDs:  []string{},
		Settings:    make(map[string]string),
	}
}

// Evidence captures metadata about an engine run.
type Evidence struct {
	EngineID      EngineID
	EngineVersion string
	RawOutput     []byte // Original engine output (for debugging)
	OutputFormat  string // e.g., "json", "sarif"
}

// RawFinding represents an unprocessed finding from an engine.
// It will be normalized into a domain Finding.
type RawFinding struct {
	RuleID      string
	Message     string
	Severity    string // Engine-specific severity string
	Confidence  string // Engine-specific confidence string
	File        string
	StartLine   int
	StartColumn int
	EndLine     int
	EndColumn   int
	Snippet     string            // Code snippet if available
	Metadata    map[string]string // Engine-specific metadata
}

// Engine defines the interface for security scanner adapters.
// Adapters in the infrastructure layer implement this interface.
type Engine interface {
	// ID returns the unique identifier for this engine.
	ID() EngineID

	// Version returns the engine's version string.
	Version() string

	// Capabilities returns what this engine can scan for.
	Capabilities() []Capability

	// IsAvailable checks if the engine binary is installed and accessible.
	IsAvailable() bool

	// Run executes the scan and returns raw findings.
	// The findings will be normalized by the application layer.
	Run(ctx context.Context, target Target, config EngineConfig) (Evidence, []RawFinding, error)
}

// EngineRegistry manages available engines.
type EngineRegistry interface {
	// Register adds an engine to the registry.
	Register(engine Engine)

	// Get returns an engine by ID.
	Get(id EngineID) (Engine, bool)

	// GetByCapability returns all engines with a specific capability.
	GetByCapability(cap Capability) []Engine

	// All returns all registered engines.
	All() []Engine

	// Available returns only engines that are installed.
	Available() []Engine
}
