// Package trivy provides an adapter for the Trivy security scanner.
package trivy

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// ScanMode determines what Trivy scans.
type ScanMode string

const (
	// ScanModeFS scans the filesystem (default).
	ScanModeFS ScanMode = "fs"
	// ScanModeImage scans a container image.
	ScanModeImage ScanMode = "image"
)

// Adapter implements the Engine interface for Trivy.
type Adapter struct {
	binaryPath string
	version    string
	scanMode   ScanMode
}

// NewAdapter creates a new Trivy adapter for filesystem scanning.
func NewAdapter() *Adapter {
	return &Adapter{
		binaryPath: "trivy",
		scanMode:   ScanModeFS,
	}
}

// NewImageAdapter creates a new Trivy adapter for container image scanning.
func NewImageAdapter() *Adapter {
	return &Adapter{
		binaryPath: "trivy",
		scanMode:   ScanModeImage,
	}
}

// NewAdapterWithPath creates a new Trivy adapter with a custom binary path.
func NewAdapterWithPath(path string, mode ScanMode) *Adapter {
	return &Adapter{
		binaryPath: path,
		scanMode:   mode,
	}
}

// ID returns the engine identifier.
func (a *Adapter) ID() ports.EngineID {
	return ports.EngineTrivy
}

// Version returns the Trivy version.
func (a *Adapter) Version() string {
	if a.version == "" {
		a.version = a.detectVersion()
	}
	return a.version
}

// Capabilities returns what this engine can scan for.
func (a *Adapter) Capabilities() []ports.Capability {
	if a.scanMode == ScanModeImage {
		return []ports.Capability{ports.CapabilityContainer, ports.CapabilityVuln}
	}
	return []ports.Capability{ports.CapabilityVuln, ports.CapabilitySecrets}
}

// IsAvailable checks if Trivy is installed and accessible.
func (a *Adapter) IsAvailable() bool {
	_, err := exec.LookPath(a.binaryPath)
	return err == nil
}

// Info returns metadata about the engine for user-facing display.
func (a *Adapter) Info() ports.EngineInfo {
	return ports.EngineInfo{
		ID:          ports.EngineTrivy,
		Name:        "Trivy",
		Description: "Comprehensive vulnerability scanner for containers, filesystems, and Git repositories",
		InstallCmd:  "brew install trivy  # or see https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
		Homepage:    "https://github.com/aquasecurity/trivy",
		Capability:  ports.CapabilityContainer,
	}
}

// Run executes Trivy and returns raw findings.
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

	// Build command arguments
	args := a.buildArgs(target, config)

	// Execute trivy
	cmd := exec.CommandContext(ctx, a.binaryPath, args...) // #nosec G204 - binary path is controlled
	if a.scanMode == ScanModeFS {
		cmd.Dir = target.Path
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	evidence.RawOutput = stdout.Bytes()

	// Trivy returns non-zero exit code when vulnerabilities exist
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 means vulnerabilities were found - this is OK
			if exitErr.ExitCode() != 1 {
				return evidence, nil, fmt.Errorf("trivy failed: %s", stderr.String())
			}
		} else {
			return evidence, nil, fmt.Errorf("trivy execution failed: %w", err)
		}
	}

	// Parse JSON output
	parser := NewParser()
	rawFindings, err := parser.Parse(stdout.Bytes())
	if err != nil {
		return evidence, nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	return evidence, rawFindings, nil
}

// buildArgs constructs the Trivy command line arguments.
func (a *Adapter) buildArgs(target ports.Target, config ports.EngineConfig) []string {
	args := []string{
		string(a.scanMode),
		"--format=json",
		"--quiet",
	}

	// Add severity filter if specified
	if config.MinSeverity > 0 {
		severities := severityToTrivy(config.MinSeverity)
		args = append(args, fmt.Sprintf("--severity=%s", severities))
	}

	// Add scanners based on mode
	if a.scanMode == ScanModeFS {
		args = append(args, "--scanners=vuln,secret")
	} else {
		args = append(args, "--scanners=vuln")
	}

	// Add skip options
	args = append(args, "--skip-dirs=.git")

	// Add target
	if a.scanMode == ScanModeImage {
		args = append(args, target.Path)
	} else {
		args = append(args, ".")
	}

	return args
}

// detectVersion runs trivy version to get version info.
func (a *Adapter) detectVersion() string {
	// #nosec G204 -- binaryPath is configured at initialization, not user input
	cmd := exec.Command(a.binaryPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse "Version: 0.45.0" format
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}

	return strings.TrimSpace(string(output))
}

// severityToTrivy converts domain severity to Trivy severity filter.
func severityToTrivy(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return "CRITICAL"
	case finding.SeverityHigh:
		return "CRITICAL,HIGH"
	case finding.SeverityMedium:
		return "CRITICAL,HIGH,MEDIUM"
	default:
		return "CRITICAL,HIGH,MEDIUM,LOW"
	}
}
