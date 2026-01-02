package staticcheck

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Adapter implements the Engine interface for staticcheck.
type Adapter struct {
	binaryPath string
	version    string
}

// NewAdapter creates a new staticcheck adapter.
func NewAdapter() *Adapter {
	return &Adapter{
		binaryPath: "staticcheck",
	}
}

// NewAdapterWithPath creates a new staticcheck adapter with a custom binary path.
func NewAdapterWithPath(path string) *Adapter {
	return &Adapter{
		binaryPath: path,
	}
}

// ID returns the engine identifier.
func (a *Adapter) ID() ports.EngineID {
	return ports.EngineStaticcheck
}

// Version returns the staticcheck version.
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

// IsAvailable checks if staticcheck is installed and accessible.
func (a *Adapter) IsAvailable() bool {
	_, err := exec.LookPath(a.binaryPath)
	return err == nil
}

// Info returns metadata about the engine for user-facing display.
func (a *Adapter) Info() ports.EngineInfo {
	return ports.EngineInfo{
		ID:          ports.EngineStaticcheck,
		Name:        "Staticcheck",
		Description: "Dead code detection - finds unused functions, types, constants, and variables",
		InstallCmd:  "go install honnef.co/go/tools/cmd/staticcheck@latest",
		Homepage:    "https://staticcheck.dev/",
		Capability:  ports.CapabilitySAST,
	}
}

// Run executes staticcheck and returns raw findings.
func (a *Adapter) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	evidence := ports.Evidence{
		EngineID:      a.ID(),
		EngineVersion: a.Version(),
		OutputFormat:  "json",
	}

	if !a.IsAvailable() {
		info := a.Info()
		return evidence, nil, fmt.Errorf("%s not found. Install with:\n  %s\n\nMore info: %s",
			info.Name, info.InstallCmd, info.Homepage)
	}

	// Validate target path to prevent command injection
	cleanPath, err := pathutil.ValidatePath(target.Path)
	if err != nil {
		return evidence, nil, fmt.Errorf("invalid target path: %w", err)
	}

	// Build command arguments
	args := a.buildArgs(target, config)

	// Execute staticcheck - path is validated above
	cmd := exec.CommandContext(ctx, a.binaryPath, args...) // #nosec G204 - binary path is controlled, target path is validated
	cmd.Dir = cleanPath

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// staticcheck returns non-zero exit code when findings exist, which is expected
	err = cmd.Run()
	evidence.RawOutput = stdout.Bytes()

	// Check for actual errors (not just findings)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 means findings were found - this is OK
			if exitErr.ExitCode() != 1 {
				return evidence, nil, fmt.Errorf("staticcheck failed: %s", stderr.String())
			}
		} else {
			return evidence, nil, fmt.Errorf("staticcheck execution failed: %w", err)
		}
	}

	// Parse JSON output
	parser := NewParser()
	rawFindings, err := parser.Parse(stdout.Bytes())
	if err != nil {
		return evidence, nil, fmt.Errorf("failed to parse staticcheck output: %w", err)
	}

	return evidence, rawFindings, nil
}

// buildArgs constructs the staticcheck command line arguments.
func (a *Adapter) buildArgs(target ports.Target, config ports.EngineConfig) []string {
	args := []string{
		"-f", "json",       // JSON output format
		"-checks", "U1000", // Only dead code detection
	}

	// Add path exclusions via -exclude flag (if supported)
	// Note: staticcheck doesn't have direct path exclusion, but we can filter after
	_ = target.Exclusions // Exclusions handled at output filtering level

	// Add the target path (./... means all packages recursively)
	args = append(args, "./...")

	return args
}

// detectVersion gets the staticcheck version.
func (a *Adapter) detectVersion() string {
	cmd := exec.Command(a.binaryPath, "-version") // #nosec G204 - binary path is controlled by adapter
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output
	// staticcheck outputs: "staticcheck 2025.1.1 (0.6.1)"
	versionStr := strings.TrimSpace(string(output))

	// Extract version number
	parts := strings.Fields(versionStr)
	if len(parts) >= 2 {
		return parts[1]
	}

	return "unknown"
}

// Ensure Adapter implements ports.Engine
var _ ports.Engine = (*Adapter)(nil)
