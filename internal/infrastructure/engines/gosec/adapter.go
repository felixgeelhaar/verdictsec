package gosec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Adapter implements the Engine interface for gosec.
type Adapter struct {
	binaryPath string
	version    string
}

// NewAdapter creates a new gosec adapter.
func NewAdapter() *Adapter {
	return &Adapter{
		binaryPath: "gosec",
	}
}

// NewAdapterWithPath creates a new gosec adapter with a custom binary path.
func NewAdapterWithPath(path string) *Adapter {
	return &Adapter{
		binaryPath: path,
	}
}

// ID returns the engine identifier.
func (a *Adapter) ID() ports.EngineID {
	return ports.EngineGosec
}

// Version returns the gosec version.
func (a *Adapter) Version() string {
	if a.version == "" {
		a.version = a.detectVersion()
	}
	return a.version
}

// Capabilities returns what this engine can scan for.
func (a *Adapter) Capabilities() []ports.Capability {
	return []ports.Capability{ports.CapabilitySAST}
}

// IsAvailable checks if gosec is installed and accessible.
func (a *Adapter) IsAvailable() bool {
	_, err := exec.LookPath(a.binaryPath)
	return err == nil
}

// Run executes gosec and returns raw findings.
func (a *Adapter) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	evidence := ports.Evidence{
		EngineID:      a.ID(),
		EngineVersion: a.Version(),
		OutputFormat:  "json",
	}

	if !a.IsAvailable() {
		return evidence, nil, fmt.Errorf("gosec binary not found: %s", a.binaryPath)
	}

	// Validate target path to prevent command injection
	cleanPath, err := pathutil.ValidatePath(target.Path)
	if err != nil {
		return evidence, nil, fmt.Errorf("invalid target path: %w", err)
	}

	// Build command arguments
	args := a.buildArgs(target, config)

	// Execute gosec - path is validated above
	cmd := exec.CommandContext(ctx, a.binaryPath, args...) // #nosec G204 - binary path is controlled, target path is validated
	cmd.Dir = cleanPath

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// gosec returns non-zero exit code when findings exist, which is expected
	err = cmd.Run()
	evidence.RawOutput = stdout.Bytes()

	// Check for actual errors (not just findings)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 means findings were found - this is OK
			if exitErr.ExitCode() != 1 {
				return evidence, nil, fmt.Errorf("gosec failed: %s", stderr.String())
			}
		} else {
			return evidence, nil, fmt.Errorf("gosec execution failed: %w", err)
		}
	}

	// Parse JSON output
	parser := NewParser()
	rawFindings, err := parser.Parse(stdout.Bytes())
	if err != nil {
		return evidence, nil, fmt.Errorf("failed to parse gosec output: %w", err)
	}

	return evidence, rawFindings, nil
}

// buildArgs constructs the gosec command line arguments.
func (a *Adapter) buildArgs(target ports.Target, config ports.EngineConfig) []string {
	args := []string{
		"-fmt=json",
		"-stdout",
		"-quiet",
	}

	// Add severity filter if specified
	if config.MinSeverity > 0 {
		args = append(args, fmt.Sprintf("-severity=%s", severityToGosec(config.MinSeverity)))
	}

	// Add exclusions
	for _, ruleID := range config.ExcludeIDs {
		args = append(args, fmt.Sprintf("-exclude=%s", ruleID))
	}

	// Add path exclusions
	if len(target.Exclusions) > 0 {
		excludePattern := strings.Join(target.Exclusions, ",")
		args = append(args, fmt.Sprintf("-exclude-dir=%s", excludePattern))
	}

	// Add the target path (./... means all packages recursively)
	args = append(args, "./...")

	return args
}

// detectVersion gets the gosec version.
func (a *Adapter) detectVersion() string {
	cmd := exec.Command(a.binaryPath, "-version") // #nosec G204 - binary path is controlled by adapter
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output (e.g., "Version: 2.18.0")
	versionStr := strings.TrimSpace(string(output))
	if strings.HasPrefix(versionStr, "Version: ") {
		return strings.TrimPrefix(versionStr, "Version: ")
	}

	// Try to extract version from different formats
	lines := strings.Split(versionStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "version") || strings.Contains(line, "Version") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if len(part) > 0 && (part[0] >= '0' && part[0] <= '9') {
					return strings.TrimSpace(part)
				}
			}
		}
	}

	return "unknown"
}

// severityToGosec converts domain severity to gosec severity string.
func severityToGosec(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "HIGH"
	case finding.SeverityMedium:
		return "MEDIUM"
	case finding.SeverityLow:
		return "LOW"
	default:
		return "LOW"
	}
}

// Ensure Adapter implements ports.Engine
var _ ports.Engine = (*Adapter)(nil)
