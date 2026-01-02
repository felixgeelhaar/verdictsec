package gitleaks

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Adapter implements the Engine interface for gitleaks.
type Adapter struct {
	binaryPath string
	version    string
	redactor   *Redactor
}

// NewAdapter creates a new gitleaks adapter.
func NewAdapter() *Adapter {
	return &Adapter{
		binaryPath: "gitleaks",
		redactor:   NewRedactor(),
	}
}

// NewAdapterWithPath creates a new gitleaks adapter with a custom binary path.
func NewAdapterWithPath(path string) *Adapter {
	return &Adapter{
		binaryPath: path,
		redactor:   NewRedactor(),
	}
}

// ID returns the engine identifier.
func (a *Adapter) ID() ports.EngineID {
	return ports.EngineGitleaks
}

// Version returns the gitleaks version.
func (a *Adapter) Version() string {
	if a.version == "" {
		a.version = a.detectVersion()
	}
	return a.version
}

// Capabilities returns what this engine can scan for.
func (a *Adapter) Capabilities() []ports.Capability {
	return []ports.Capability{ports.CapabilitySecrets}
}

// IsAvailable checks if gitleaks is installed and accessible.
func (a *Adapter) IsAvailable() bool {
	_, err := exec.LookPath(a.binaryPath)
	return err == nil
}

// Info returns metadata about the engine for user-facing display.
func (a *Adapter) Info() ports.EngineInfo {
	return ports.EngineInfo{
		ID:          ports.EngineGitleaks,
		Name:        "Gitleaks",
		Description: "Secrets detector - finds hardcoded credentials and API keys",
		InstallCmd:  "go install github.com/gitleaks/gitleaks/v8@latest",
		Homepage:    "https://github.com/gitleaks/gitleaks",
		Capability:  ports.CapabilitySecrets,
	}
}

// Run executes gitleaks and returns raw findings.
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

	// Execute gitleaks - path is validated above
	cmd := exec.CommandContext(ctx, a.binaryPath, args...) // #nosec G204 - binary path is controlled, target path is validated
	cmd.Dir = cleanPath

	// Configure environment with any additional settings
	cmd.Env = a.buildEnv(config)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// gitleaks returns exit code 1 when leaks are found
	err = cmd.Run()
	evidence.RawOutput = stdout.Bytes()

	// Check for actual errors
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 means leaks were found - this is OK
			// Exit code 0 means no leaks
			if exitErr.ExitCode() != 1 && exitErr.ExitCode() != 0 {
				return evidence, nil, fmt.Errorf("gitleaks failed: %s", stderr.String())
			}
		} else {
			return evidence, nil, fmt.Errorf("gitleaks execution failed: %w", err)
		}
	}

	// Parse JSON output
	parser := NewParser()
	rawFindings, err := parser.Parse(stdout.Bytes())
	if err != nil {
		return evidence, nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	// Redact secrets if enabled (default)
	redact := true
	if redactSetting, ok := config.Settings["redact"]; ok {
		redact = redactSetting == "true"
	}

	if redact {
		for i := range rawFindings {
			rawFindings[i] = a.redactor.RedactFinding(rawFindings[i])
		}
	}

	return evidence, rawFindings, nil
}

// buildArgs constructs the gitleaks command line arguments.
func (a *Adapter) buildArgs(target ports.Target, config ports.EngineConfig) []string {
	args := []string{
		"detect",
		"--report-format=json",
		"--report-path=/dev/stdout",
		"--no-banner",
	}

	// Scan mode: source (files) or git (git history)
	if mode, ok := config.Settings["mode"]; ok && mode == "git" {
		// Git mode scans git history
		args = append(args, "--source=.")
	} else {
		// Default: no-git mode scans current files only
		args = append(args, "--no-git")
		args = append(args, "--source=.")
	}

	// Add custom config path if specified
	if configPath, ok := config.Settings["config"]; ok {
		args = append(args, fmt.Sprintf("--config=%s", configPath))
	}

	// Add exclusions
	for _, pattern := range target.Exclusions {
		args = append(args, fmt.Sprintf("--exclude-path=%s", pattern))
	}

	return args
}

// buildEnv constructs the environment for gitleaks execution.
// It inherits the parent environment and adds any enterprise credentials.
func (a *Adapter) buildEnv(config ports.EngineConfig) []string {
	// Start with parent environment
	env := os.Environ()

	// Add license from config if specified
	// Supports: license_env (reference to env var) or license (direct value)
	if licenseEnv, ok := config.Settings["license_env"]; ok {
		// Reference to another env var (e.g., "GITLEAKS_LICENSE")
		if val := os.Getenv(licenseEnv); val != "" {
			env = append(env, "GITLEAKS_LICENSE="+val)
		}
	} else if license, ok := config.Settings["license"]; ok {
		// Direct value (less recommended for security)
		env = append(env, "GITLEAKS_LICENSE="+license)
	}

	return env
}

// detectVersion gets the gitleaks version.
func (a *Adapter) detectVersion() string {
	cmd := exec.Command(a.binaryPath, "version") // #nosec G204 - binary path is controlled by adapter
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output (e.g., "v8.18.0")
	versionStr := strings.TrimSpace(string(output))
	if strings.HasPrefix(versionStr, "v") {
		return versionStr
	}

	return "unknown"
}

// Ensure Adapter implements ports.Engine
var _ ports.Engine = (*Adapter)(nil)
