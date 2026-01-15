package license

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Adapter wraps go-licenses for license compliance scanning.
type Adapter struct {
	version     string
	versionOnce sync.Once
}

// NewAdapter creates a new go-licenses adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// ID returns the engine identifier.
func (a *Adapter) ID() ports.EngineID {
	return ports.EngineLicense
}

// Version returns the go-licenses version.
func (a *Adapter) Version() string {
	a.versionOnce.Do(func() {
		cmd := exec.Command("go-licenses", "version")
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
	return []ports.Capability{ports.CapabilityLicense}
}

// IsAvailable checks if go-licenses is installed.
func (a *Adapter) IsAvailable() bool {
	_, err := exec.LookPath("go-licenses")
	return err == nil
}

// Info returns engine metadata.
func (a *Adapter) Info() ports.EngineInfo {
	return ports.EngineInfo{
		ID:          ports.EngineLicense,
		Name:        "go-licenses",
		Description: "Detects and classifies licenses in Go dependencies",
		InstallCmd:  "go install github.com/google/go-licenses@latest",
		Homepage:    "https://github.com/google/go-licenses",
		Capability:  ports.CapabilityLicense,
	}
}

// LicenseInfo represents parsed license information.
type LicenseInfo struct {
	Module     string `json:"module"`
	Version    string `json:"version"`
	License    string `json:"license"`
	LicenseURL string `json:"license_url"`
}

// Run executes the license scan.
func (a *Adapter) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	if _, err := pathutil.ValidatePath(target.Path); err != nil {
		return ports.Evidence{}, nil, fmt.Errorf("invalid target path: %w", err)
	}

	// Build arguments for go-licenses report
	args := []string{"report", "--template", "{{.Name}},{{.LicenseName}},{{.LicenseURL}}"}
	args = append(args, target.Path+"/...")

	cmd := exec.CommandContext(ctx, "go-licenses", args...)
	cmd.Dir = target.Path

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// go-licenses returns exit code 1 if there are license issues, but still produces output
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() > 1 {
			return ports.Evidence{}, nil, fmt.Errorf("go-licenses failed: %w\nstderr: %s", err, stderr.String())
		}
	}

	// Parse CSV output
	findings, err := a.parseOutput(stdout.Bytes(), config)
	if err != nil {
		return ports.Evidence{}, nil, fmt.Errorf("failed to parse go-licenses output: %w", err)
	}

	evidence := ports.Evidence{
		EngineID:      ports.EngineLicense,
		EngineVersion: a.Version(),
		RawOutput:     stdout.Bytes(),
		OutputFormat:  "csv",
	}

	return evidence, findings, nil
}

// parseOutput parses go-licenses CSV output and generates findings for policy violations.
func (a *Adapter) parseOutput(data []byte, config ports.EngineConfig) ([]ports.RawFinding, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1 // Allow variable fields

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	// Get policy from settings
	forbidden := getStringSlice(config.Settings, "forbidden")
	restricted := getStringSlice(config.Settings, "restricted")
	allowed := getStringSlice(config.Settings, "allowed")

	var findings []ports.RawFinding
	for _, record := range records {
		if len(record) < 2 {
			continue
		}

		module := record[0]
		license := record[1]
		licenseURL := ""
		if len(record) > 2 {
			licenseURL = record[2]
		}

		// Skip if empty
		if module == "" || license == "" {
			continue
		}

		// Determine severity based on license type
		severity := classifyLicense(license, forbidden, restricted, allowed)
		if severity == "" {
			continue // Not a policy violation
		}

		finding := ports.RawFinding{
			RuleID:   "license-" + normalizeLicenseID(license),
			Message:  fmt.Sprintf("Dependency %s uses %s license", module, license),
			Severity: severity,
			File:     "go.mod",
			Metadata: map[string]string{
				"module":      module,
				"license":     license,
				"license_url": licenseURL,
				"type":        "license",
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// classifyLicense determines the severity based on license policy.
func classifyLicense(license string, forbidden, restricted, allowed []string) string {
	normalizedLicense := strings.ToUpper(strings.TrimSpace(license))

	// Default forbidden licenses if not specified
	if len(forbidden) == 0 {
		forbidden = []string{
			"AGPL-1.0", "AGPL-3.0", "AGPL-1.0-ONLY", "AGPL-3.0-ONLY",
			"AGPL-1.0-OR-LATER", "AGPL-3.0-OR-LATER",
			"SSPL", "SSPL-1.0",
			"COMMONS CLAUSE", "CC-BY-NC", "CC-BY-NC-SA", "CC-BY-NC-ND",
		}
	}

	// Default restricted licenses if not specified
	if len(restricted) == 0 {
		restricted = []string{
			"GPL-2.0", "GPL-3.0", "GPL-2.0-ONLY", "GPL-3.0-ONLY",
			"GPL-2.0-OR-LATER", "GPL-3.0-OR-LATER",
			"LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
			"MPL-1.0", "MPL-1.1", "MPL-2.0",
			"EPL-1.0", "EPL-2.0",
			"CDDL-1.0", "CDDL-1.1",
		}
	}

	// Check forbidden (CRITICAL)
	for _, f := range forbidden {
		if strings.Contains(normalizedLicense, strings.ToUpper(f)) {
			return "CRITICAL"
		}
	}

	// Check restricted (HIGH)
	for _, r := range restricted {
		if strings.Contains(normalizedLicense, strings.ToUpper(r)) {
			return "HIGH"
		}
	}

	// Check unknown license
	if normalizedLicense == "UNKNOWN" || normalizedLicense == "" {
		return "MEDIUM"
	}

	// If allowed list is specified, check against it
	if len(allowed) > 0 {
		for _, a := range allowed {
			if strings.Contains(normalizedLicense, strings.ToUpper(a)) {
				return "" // Allowed, no finding
			}
		}
		// Not in allowed list - flag as low priority for review
		return "LOW"
	}

	// No finding for permissive licenses
	return ""
}

// normalizeLicenseID creates a safe rule ID from license name.
func normalizeLicenseID(license string) string {
	result := strings.ToLower(license)
	result = strings.ReplaceAll(result, " ", "-")
	result = strings.ReplaceAll(result, ".", "-")
	return result
}

// getStringSlice extracts a string slice from settings.
func getStringSlice(settings map[string]string, key string) []string {
	val, ok := settings[key]
	if !ok || val == "" {
		return nil
	}

	// Try JSON array first
	var result []string
	if err := json.Unmarshal([]byte(val), &result); err == nil {
		return result
	}

	// Fall back to comma-separated
	parts := strings.Split(val, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}
