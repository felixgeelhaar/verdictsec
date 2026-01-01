package syft

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Adapter implements the Engine interface for syft.
// Syft is an artifact-level SBOM generator for containers, binaries, and multi-ecosystem projects.
type Adapter struct {
	binaryPath string
	version    string
}

// NewAdapter creates a new syft adapter.
func NewAdapter() *Adapter {
	return &Adapter{
		binaryPath: "syft",
	}
}

// NewAdapterWithPath creates a new syft adapter with a custom binary path.
func NewAdapterWithPath(path string) *Adapter {
	return &Adapter{
		binaryPath: path,
	}
}

// ID returns the engine identifier.
func (a *Adapter) ID() ports.EngineID {
	return ports.EngineSyft
}

// Version returns the syft version.
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

// IsAvailable checks if syft is installed and accessible.
func (a *Adapter) IsAvailable() bool {
	_, err := exec.LookPath(a.binaryPath)
	return err == nil
}

// Info returns metadata about the engine for user-facing display.
func (a *Adapter) Info() ports.EngineInfo {
	return ports.EngineInfo{
		ID:          ports.EngineSyft,
		Name:        "Syft",
		Description: "Artifact SBOM generator - creates software bill of materials from containers, binaries, and filesystems",
		InstallCmd:  "go install github.com/anchore/syft/cmd/syft@latest",
		Homepage:    "https://github.com/anchore/syft",
		Capability:  ports.CapabilitySBOM,
	}
}

// Run executes syft and returns the SBOM.
// Note: SBOM generation doesn't produce findings, but the raw output contains the SBOM.
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

	// Execute syft - path is validated above
	cmd := exec.CommandContext(ctx, a.binaryPath, args...) // #nosec G204 - binary path is controlled, target path is validated
	cmd.Dir = cleanPath

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	evidence.RawOutput = stdout.Bytes()

	if err != nil {
		return evidence, nil, fmt.Errorf("syft failed: %s", stderr.String())
	}

	// Parse the SBOM to extract artifact information
	parser := NewParser()
	rawFindings, err := parser.Parse(stdout.Bytes())
	if err != nil {
		return evidence, nil, fmt.Errorf("failed to parse syft output: %w", err)
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

// buildArgs constructs the syft command line arguments.
func (a *Adapter) buildArgs(target ports.Target, config ports.EngineConfig) []string {
	// Default to scanning current directory
	scanTarget := "dir:."

	// Check for specific source type from settings
	if sourceType, ok := config.Settings["source_type"]; ok {
		switch sourceType {
		case "image":
			// Container image scanning
			if imageName, ok := config.Settings["image"]; ok {
				scanTarget = imageName
			}
		case "file":
			// File/binary scanning
			if filePath, ok := config.Settings["file"]; ok {
				scanTarget = "file:" + filePath
			}
		case "dir":
			// Directory scanning (default)
			scanTarget = "dir:."
		}
	}

	args := []string{
		scanTarget,
		"-o", "json",
		"--quiet",
	}

	// Output format override (cyclonedx-json, spdx-json, etc.)
	if outputFormat, ok := config.Settings["output_format"]; ok {
		args[2] = outputFormat
	}

	// Exclude patterns
	for _, exclusion := range target.Exclusions {
		args = append(args, "--exclude", exclusion)
	}

	// Scope: all-layers (for containers) or squashed
	if scope, ok := config.Settings["scope"]; ok {
		args = append(args, "--scope", scope)
	}

	// Config file
	if configFile, ok := config.Settings["config"]; ok {
		args = append(args, "--config", configFile)
	}

	return args
}

// detectVersion gets the syft version.
func (a *Adapter) detectVersion() string {
	cmd := exec.Command(a.binaryPath, "version") // #nosec G204 - binary path is controlled by adapter
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output
	// Syft outputs: "syft 0.x.x" or similar format
	versionStr := strings.TrimSpace(string(output))
	lines := strings.Split(versionStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for version line
		if strings.HasPrefix(line, "Version:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
		// Some versions just output "syft x.y.z"
		if strings.HasPrefix(line, "syft") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
		// Try to find a version number
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "v") || (len(part) > 0 && part[0] >= '0' && part[0] <= '9') {
				return strings.TrimSpace(part)
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
