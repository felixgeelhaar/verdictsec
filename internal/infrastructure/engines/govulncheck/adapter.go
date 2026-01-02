package govulncheck

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

// Info returns metadata about the engine for user-facing display.
func (a *Adapter) Info() ports.EngineInfo {
	return ports.EngineInfo{
		ID:          ports.EngineGovulncheck,
		Name:        "Govulncheck",
		Description: "Go vulnerability scanner - finds known vulnerabilities in dependencies",
		InstallCmd:  "go install golang.org/x/vuln/cmd/govulncheck@latest",
		Homepage:    "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
		Capability:  ports.CapabilityVuln,
	}
}

// Run executes govulncheck and returns raw findings.
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

	// Execute govulncheck - path is validated above
	cmd := exec.CommandContext(ctx, a.binaryPath, args...) // #nosec G204 - binary path is controlled, target path is validated
	cmd.Dir = cleanPath

	// Configure environment with any additional settings (GOPRIVATE, GONOPROXY, etc.)
	cmd.Env = a.buildEnv(config)

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

// buildEnv constructs the environment for govulncheck execution.
// It inherits the parent environment and adds private module configuration.
func (a *Adapter) buildEnv(config ports.EngineConfig) []string {
	// Start with parent environment
	env := os.Environ()

	// Add GOPRIVATE from config if specified
	// Supports: goprivate_env (reference to env var) or goprivate (direct value)
	if goprivateEnv, ok := config.Settings["goprivate_env"]; ok {
		// Reference to another env var (e.g., "GOPRIVATE")
		if val := os.Getenv(goprivateEnv); val != "" {
			env = append(env, "GOPRIVATE="+val)
		}
	} else if goprivate, ok := config.Settings["goprivate"]; ok {
		// Direct value
		env = append(env, "GOPRIVATE="+goprivate)
	}

	// Add GONOPROXY from config if specified
	// Supports: gonoproxy_env (reference to env var) or gonoproxy (direct value)
	if gonoproxyEnv, ok := config.Settings["gonoproxy_env"]; ok {
		// Reference to another env var (e.g., "GONOPROXY")
		if val := os.Getenv(gonoproxyEnv); val != "" {
			env = append(env, "GONOPROXY="+val)
		}
	} else if gonoproxy, ok := config.Settings["gonoproxy"]; ok {
		// Direct value
		env = append(env, "GONOPROXY="+gonoproxy)
	}

	// Add GONOSUMDB from config if specified
	// Supports: gonosumdb_env (reference to env var) or gonosumdb (direct value)
	if gonosumdbEnv, ok := config.Settings["gonosumdb_env"]; ok {
		// Reference to another env var (e.g., "GONOSUMDB")
		if val := os.Getenv(gonosumdbEnv); val != "" {
			env = append(env, "GONOSUMDB="+val)
		}
	} else if gonosumdb, ok := config.Settings["gonosumdb"]; ok {
		// Direct value
		env = append(env, "GONOSUMDB="+gonosumdb)
	}

	return env
}

// detectVersion gets the govulncheck version.
func (a *Adapter) detectVersion() string {
	cmd := exec.Command(a.binaryPath, "-version") // #nosec G204 - binary path is controlled by adapter
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output
	// govulncheck outputs: "Go: go1.x\nScanner: govulncheck@v1.1.4\nDB: ..."
	versionStr := strings.TrimSpace(string(output))
	lines := strings.Split(versionStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for "Scanner: govulncheck@v1.1.4" format
		if strings.HasPrefix(line, "Scanner:") {
			// Extract version from "govulncheck@v1.1.4"
			if idx := strings.Index(line, "@"); idx != -1 {
				version := strings.TrimSpace(line[idx+1:])
				if version != "" {
					return version
				}
			}
		}
	}

	return "unknown"
}

// Ensure Adapter implements ports.Engine
var _ ports.Engine = (*Adapter)(nil)
