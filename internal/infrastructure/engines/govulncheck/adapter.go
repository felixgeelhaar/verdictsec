package govulncheck

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

// Adapter implements the Engine interface for govulncheck.
type Adapter struct {
	binaryPath string
	version    string
}

// NewAdapter creates a new govulncheck adapter.
func NewAdapter() *Adapter {
	return &Adapter{
		binaryPath: "govulncheck",
	}
}

// NewAdapterWithPath creates a new govulncheck adapter with a custom binary path.
func NewAdapterWithPath(path string) *Adapter {
	return &Adapter{
		binaryPath: path,
	}
}

// ID returns the engine identifier.
func (a *Adapter) ID() ports.EngineID {
	return ports.EngineGovulncheck
}

// Version returns the govulncheck version.
func (a *Adapter) Version() string {
	if a.version == "" {
		a.version = a.detectVersion()
	}
	return a.version
}

// Capabilities returns what this engine can scan for.
func (a *Adapter) Capabilities() []ports.Capability {
	return []ports.Capability{ports.CapabilityVuln}
}

// IsAvailable checks if govulncheck is installed and accessible.
func (a *Adapter) IsAvailable() bool {
	_, err := exec.LookPath(a.binaryPath)
	return err == nil
}

// Run executes govulncheck and returns raw findings.
func (a *Adapter) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	evidence := ports.Evidence{
		EngineID:      a.ID(),
		EngineVersion: a.Version(),
		OutputFormat:  "json",
	}

	if !a.IsAvailable() {
		return evidence, nil, fmt.Errorf("govulncheck binary not found: %s", a.binaryPath)
	}

	// Validate target path to prevent command injection
	cleanPath, err := pathutil.ValidatePath(target.Path)
	if err != nil {
		return evidence, nil, fmt.Errorf("invalid target path: %w", err)
	}

	// Build command arguments
	args := a.buildArgs(target, config)

	// Execute govulncheck - path is validated above
	cmd := exec.CommandContext(ctx, a.binaryPath, args...) // #nosec G204 - binary path is controlled, target path is validated
	cmd.Dir = cleanPath

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// govulncheck returns exit code 3 when vulnerabilities are found
	err = cmd.Run()
	evidence.RawOutput = stdout.Bytes()

	// Check for actual errors
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 3 means vulnerabilities were found - this is OK
			// Exit code 0 means no vulnerabilities
			// Any other exit code is an error
			if exitErr.ExitCode() != 3 && exitErr.ExitCode() != 0 {
				return evidence, nil, fmt.Errorf("govulncheck failed: %s", stderr.String())
			}
		} else {
			return evidence, nil, fmt.Errorf("govulncheck execution failed: %w", err)
		}
	}

	// Parse JSON output
	parser := NewParser()
	rawFindings, err := parser.Parse(stdout.Bytes())
	if err != nil {
		return evidence, nil, fmt.Errorf("failed to parse govulncheck output: %w", err)
	}

	return evidence, rawFindings, nil
}

// buildArgs constructs the govulncheck command line arguments.
func (a *Adapter) buildArgs(target ports.Target, config ports.EngineConfig) []string {
	args := []string{
		"-format=json",
	}

	// Add scan mode if specified in settings
	if mode, ok := config.Settings["mode"]; ok {
		args = append(args, fmt.Sprintf("-mode=%s", mode))
	}

	// Add the target path
	args = append(args, "./...")

	return args
}

// detectVersion gets the govulncheck version.
func (a *Adapter) detectVersion() string {
	cmd := exec.Command(a.binaryPath, "-version") // #nosec G204 - binary path is controlled by adapter
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output
	versionStr := strings.TrimSpace(string(output))
	lines := strings.Split(versionStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "govulncheck") || strings.Contains(line, "v") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "v") {
					return part
				}
			}
		}
	}

	// Try to find version pattern
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && (line[0] == 'v' || (line[0] >= '0' && line[0] <= '9')) {
			return line
		}
	}

	return "unknown"
}

// severityFromCVSS converts a CVSS score to domain severity.
func severityFromCVSS(score float64) finding.Severity {
	switch {
	case score >= 9.0:
		return finding.SeverityCritical
	case score >= 7.0:
		return finding.SeverityHigh
	case score >= 4.0:
		return finding.SeverityMedium
	case score > 0:
		return finding.SeverityLow
	default:
		return finding.SeverityUnknown
	}
}

// Ensure Adapter implements ports.Engine
var _ ports.Engine = (*Adapter)(nil)
