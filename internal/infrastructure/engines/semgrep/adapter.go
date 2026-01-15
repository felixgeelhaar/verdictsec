package semgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Adapter wraps semgrep for SAST scanning.
type Adapter struct {
	version     string
	versionOnce sync.Once
}

// NewAdapter creates a new semgrep adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// ID returns the engine identifier.
func (a *Adapter) ID() ports.EngineID {
	return ports.EngineSemgrep
}

// Version returns the semgrep version.
func (a *Adapter) Version() string {
	a.versionOnce.Do(func() {
		cmd := exec.Command("semgrep", "--version")
		out, err := cmd.Output()
		if err != nil {
			a.version = "unknown"
			return
		}
		a.version = strings.TrimSpace(string(out))
	})
	return a.version
}

// Capabilities returns the engine capabilities.
func (a *Adapter) Capabilities() []ports.Capability {
	return []ports.Capability{ports.CapabilitySAST}
}

// IsAvailable checks if semgrep is installed.
func (a *Adapter) IsAvailable() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

// Info returns engine metadata.
func (a *Adapter) Info() ports.EngineInfo {
	return ports.EngineInfo{
		ID:          ports.EngineSemgrep,
		Name:        "Semgrep",
		Description: "Fast, lightweight static analysis with custom rules support",
		InstallCmd:  "pip install semgrep",
		Homepage:    "https://semgrep.dev",
		Capability:  ports.CapabilitySAST,
	}
}

// SemgrepOutput represents the JSON output from semgrep.
type SemgrepOutput struct {
	Results []SemgrepResult `json:"results"`
	Errors  []SemgrepError  `json:"errors"`
	Version string          `json:"version"`
}

// SemgrepResult represents a single finding from semgrep.
type SemgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"start"`
	End struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		Message  string            `json:"message"`
		Severity string            `json:"severity"`
		Metadata map[string]any    `json:"metadata"`
		Lines    string            `json:"lines"`
		Fix      string            `json:"fix"`
		Dataflow map[string]any    `json:"dataflow_trace,omitempty"`
	} `json:"extra"`
}

// SemgrepError represents an error from semgrep.
type SemgrepError struct {
	Code    int    `json:"code"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Path    string `json:"path"`
}

// Run executes the semgrep scan.
func (a *Adapter) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	if _, err := pathutil.ValidatePath(target.Path); err != nil {
		return ports.Evidence{}, nil, fmt.Errorf("invalid target path: %w", err)
	}

	// Build arguments
	args := a.buildArgs(target, config)

	cmd := exec.CommandContext(ctx, "semgrep", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// semgrep returns exit code 1 if there are findings
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return ports.Evidence{}, nil, fmt.Errorf("semgrep failed: %w\nstderr: %s", err, stderr.String())
		}
		// Exit code 1 = findings found, that's OK
		// Exit code 2+ = actual error
		if exitErr.ExitCode() > 1 {
			return ports.Evidence{}, nil, fmt.Errorf("semgrep error (exit %d): %s", exitErr.ExitCode(), stderr.String())
		}
	}

	// Parse JSON output
	findings, err := a.parseOutput(stdout.Bytes(), config)
	if err != nil {
		return ports.Evidence{}, nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	evidence := ports.Evidence{
		EngineID:      ports.EngineSemgrep,
		EngineVersion: a.Version(),
		RawOutput:     stdout.Bytes(),
		OutputFormat:  "json",
	}

	return evidence, findings, nil
}

// buildArgs constructs the semgrep command arguments.
func (a *Adapter) buildArgs(target ports.Target, config ports.EngineConfig) []string {
	args := []string{
		"scan",
		"--json",
		"--quiet",
	}

	// Add config/rules
	if ruleConfig, ok := config.Settings["config"]; ok && ruleConfig != "" {
		args = append(args, "--config", ruleConfig)
	} else {
		// Default to auto-detect rules for Go
		args = append(args, "--config", "auto")
	}

	// Add severity filter
	if severity, ok := config.Settings["severity"]; ok && severity != "" {
		args = append(args, "--severity", severity)
	}

	// Add exclusions
	for _, excl := range config.ExcludeIDs {
		args = append(args, "--exclude-rule", excl)
	}

	// Add path exclusions
	for _, excl := range target.Exclusions {
		args = append(args, "--exclude", excl)
	}

	// Add target path
	args = append(args, target.Path)

	return args
}

// parseOutput parses semgrep JSON output.
func (a *Adapter) parseOutput(data []byte, config ports.EngineConfig) ([]ports.RawFinding, error) {
	var output SemgrepOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal semgrep output: %w", err)
	}

	var findings []ports.RawFinding
	for _, result := range output.Results {
		// Check exclusions
		excluded := false
		for _, excl := range config.ExcludeIDs {
			if result.CheckID == excl {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Extract CWE if available
		cwe := ""
		if result.Extra.Metadata != nil {
			if cweList, ok := result.Extra.Metadata["cwe"].([]any); ok && len(cweList) > 0 {
				if cweStr, ok := cweList[0].(string); ok {
					cwe = cweStr
				}
			}
		}

		finding := ports.RawFinding{
			RuleID:      result.CheckID,
			Message:     result.Extra.Message,
			Severity:    mapSemgrepSeverity(result.Extra.Severity),
			Confidence:  "HIGH", // Semgrep is high confidence
			File:        result.Path,
			StartLine:   result.Start.Line,
			StartColumn: result.Start.Col,
			EndLine:     result.End.Line,
			EndColumn:   result.End.Col,
			Snippet:     result.Extra.Lines,
			Metadata: map[string]string{
				"cwe": cwe,
				"fix": result.Extra.Fix,
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// mapSemgrepSeverity maps semgrep severity to normalized severity.
func mapSemgrepSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "ERROR":
		return "HIGH"
	case "WARNING":
		return "MEDIUM"
	case "INFO":
		return "LOW"
	default:
		return "MEDIUM"
	}
}
