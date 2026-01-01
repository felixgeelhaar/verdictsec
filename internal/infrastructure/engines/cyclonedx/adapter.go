package cyclonedx

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Adapter implements the Engine interface for cyclonedx-gomod.
// This adapter generates SBOMs rather than finding security issues.
type Adapter struct {
	binaryPath string
	version    string
}

// NewAdapter creates a new cyclonedx-gomod adapter.
func NewAdapter() *Adapter {
	return &Adapter{
		binaryPath: "cyclonedx-gomod",
	}
}

// NewAdapterWithPath creates a new cyclonedx-gomod adapter with a custom binary path.
func NewAdapterWithPath(path string) *Adapter {
	return &Adapter{
		binaryPath: path,
	}
}

// ID returns the engine identifier.
func (a *Adapter) ID() ports.EngineID {
	return ports.EngineCycloneDX
}

// Version returns the cyclonedx-gomod version.
func (a *Adapter) Version() string {
	if a.version == "" {
		a.version = a.detectVersion()
	}
	return a.version
}

// Capabilities returns what this engine can do.
func (a *Adapter) Capabilities() []ports.Capability {
	return []ports.Capability{ports.CapabilitySBOM}
}

// IsAvailable checks if cyclonedx-gomod is installed and accessible.
func (a *Adapter) IsAvailable() bool {
	_, err := exec.LookPath(a.binaryPath)
	return err == nil
}

// Run executes cyclonedx-gomod and returns the SBOM.
// Note: SBOM generation doesn't produce findings, but the raw output contains the SBOM.
func (a *Adapter) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	evidence := ports.Evidence{
		EngineID:      a.ID(),
		EngineVersion: a.Version(),
		OutputFormat:  "json",
	}

	if !a.IsAvailable() {
		return evidence, nil, fmt.Errorf("cyclonedx-gomod binary not found: %s", a.binaryPath)
	}

	// Validate target path to prevent command injection
	cleanPath, err := pathutil.ValidatePath(target.Path)
	if err != nil {
		return evidence, nil, fmt.Errorf("invalid target path: %w", err)
	}

	// Build command arguments
	args := a.buildArgs(target, config)

	// Execute cyclonedx-gomod - path is validated above
	cmd := exec.CommandContext(ctx, a.binaryPath, args...) // #nosec G204 - binary path is controlled, target path is validated
	cmd.Dir = cleanPath

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	evidence.RawOutput = stdout.Bytes()

	if err != nil {
		return evidence, nil, fmt.Errorf("cyclonedx-gomod failed: %s", stderr.String())
	}

	// Parse the SBOM to extract component information
	parser := NewParser()
	rawFindings, err := parser.Parse(stdout.Bytes())
	if err != nil {
		return evidence, nil, fmt.Errorf("failed to parse cyclonedx-gomod output: %w", err)
	}

	return evidence, rawFindings, nil
}

// GenerateSBOM generates an SBOM and returns it as raw bytes.
func (a *Adapter) GenerateSBOM(ctx context.Context, target ports.Target, config ports.EngineConfig) ([]byte, error) {
	evidence, _, err := a.Run(ctx, target, config)
	if err != nil {
		return nil, err
	}
	return evidence.RawOutput, nil
}

// buildArgs constructs the cyclonedx-gomod command line arguments.
func (a *Adapter) buildArgs(target ports.Target, config ports.EngineConfig) []string {
	args := []string{
		"mod",
		"-json",
	}

	// Output type: module (default), app, or std
	if outputType, ok := config.Settings["type"]; ok {
		args = append(args, fmt.Sprintf("-type=%s", outputType))
	}

	// Include test dependencies
	if includeTest, ok := config.Settings["include_test"]; ok && includeTest == "true" {
		args = append(args, "-test")
	}

	// Include standard library
	if includeStd, ok := config.Settings["include_std"]; ok && includeStd == "true" {
		args = append(args, "-std")
	}

	// Specify go.mod path if not in target root
	if gomodPath, ok := config.Settings["gomod"]; ok {
		args = append(args, fmt.Sprintf("-mod=%s", gomodPath))
	}

	return args
}

// detectVersion gets the cyclonedx-gomod version.
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
		if strings.Contains(line, "version") || strings.HasPrefix(line, "v") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "v") || (len(part) > 0 && part[0] >= '0' && part[0] <= '9') {
					return strings.TrimSpace(part)
				}
			}
		}
	}

	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}

	return "unknown"
}

// Ensure Adapter implements ports.Engine
var _ ports.Engine = (*Adapter)(nil)
