package mcp

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	cfg := config.DefaultConfig()
	server := NewServer(cfg)

	require.NotNil(t, server)
	assert.NotNil(t, server.mcpServer)
	assert.NotNil(t, server.config)
	assert.NotNil(t, server.registry)
}

func TestScanInput_Defaults(t *testing.T) {
	input := ScanInput{}

	assert.Empty(t, input.Path)
	assert.Empty(t, input.Engines)
	assert.False(t, input.Strict)
}

func TestScanResult_Structure(t *testing.T) {
	result := &ScanResult{
		Status:        "completed",
		TotalCount:    5,
		CriticalCount: 1,
		HighCount:     2,
		MediumCount:   1,
		LowCount:      1,
		Duration:      "1.5s",
		Findings: []FindingInfo{
			{
				ID:          "finding-1",
				Engine:      "gosec",
				RuleID:      "G104",
				Severity:    "HIGH",
				Message:     "Potential security issue",
				File:        "main.go",
				Line:        42,
				Fingerprint: "abc123",
			},
		},
	}

	assert.Equal(t, "completed", result.Status)
	assert.Equal(t, 5, result.TotalCount)
	assert.Equal(t, 1, result.CriticalCount)
	assert.Equal(t, 2, result.HighCount)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "gosec", result.Findings[0].Engine)
}

func TestBaselineAddInput_Defaults(t *testing.T) {
	input := BaselineAddInput{}

	assert.Empty(t, input.Path)
	assert.Empty(t, input.Output)
}

func TestBaselineResult_Structure(t *testing.T) {
	result := &BaselineResult{
		Status:       "created",
		Path:         ".verdict/baseline.json",
		EntriesAdded: 10,
		TotalEntries: 10,
	}

	assert.Equal(t, "created", result.Status)
	assert.Equal(t, ".verdict/baseline.json", result.Path)
	assert.Equal(t, 10, result.EntriesAdded)
}

func TestPolicyCheckInput_Defaults(t *testing.T) {
	input := PolicyCheckInput{}

	assert.Empty(t, input.Path)
}

func TestPolicyCheckResult_Structure(t *testing.T) {
	result := &PolicyCheckResult{
		Decision:      "PASS",
		FailThreshold: "HIGH",
		WarnThreshold: "MEDIUM",
		Violations:    0,
		Warnings:      2,
		Messages:      []string{"2 medium severity findings"},
	}

	assert.Equal(t, "PASS", result.Decision)
	assert.Equal(t, "HIGH", result.FailThreshold)
	assert.Equal(t, 0, result.Violations)
	assert.Equal(t, 2, result.Warnings)
	assert.Len(t, result.Messages, 1)
}

func TestGetModeString(t *testing.T) {
	tests := []struct {
		name     string
		strict   bool
		expected string
	}{
		{"strict mode", true, "ci"},
		{"local mode", false, "local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getModeString(tt.strict)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJoin(t *testing.T) {
	tests := []struct {
		name     string
		strs     []string
		sep      string
		expected string
	}{
		{"empty slice", []string{}, ",", ""},
		{"single element", []string{"a"}, ",", "a"},
		{"multiple elements", []string{"a", "b", "c"}, ",", "a,b,c"},
		{"different separator", []string{"1", "2", "3"}, "-", "1-2-3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := join(tt.strs, tt.sep)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindingInfo_Structure(t *testing.T) {
	info := FindingInfo{
		ID:          "test-id",
		Engine:      "gosec",
		RuleID:      "G101",
		Severity:    "CRITICAL",
		Message:     "Hardcoded credentials",
		File:        "config.go",
		Line:        15,
		Fingerprint: "fingerprint123",
	}

	assert.Equal(t, "test-id", info.ID)
	assert.Equal(t, "gosec", info.Engine)
	assert.Equal(t, "G101", info.RuleID)
	assert.Equal(t, "CRITICAL", info.Severity)
	assert.Equal(t, "Hardcoded credentials", info.Message)
	assert.Equal(t, "config.go", info.File)
	assert.Equal(t, 15, info.Line)
	assert.Equal(t, "fingerprint123", info.Fingerprint)
}

func TestBaselineAddInput_WithReason(t *testing.T) {
	input := BaselineAddInput{
		Path:   "/project",
		Output: ".verdict/baseline.json",
		Reason: "Initial baseline for legacy code",
	}

	assert.Equal(t, "/project", input.Path)
	assert.Equal(t, ".verdict/baseline.json", input.Output)
	assert.Equal(t, "Initial baseline for legacy code", input.Reason)
}

func TestServer_RegistryInitialization(t *testing.T) {
	cfg := config.DefaultConfig()
	server := NewServer(cfg)

	// Verify registry is properly initialized
	require.NotNil(t, server.registry)
}

func TestServer_ConfigStored(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Policy.Threshold.FailOn = "CRITICAL"
	server := NewServer(cfg)

	// Verify config is properly stored
	assert.Equal(t, "CRITICAL", server.config.Policy.Threshold.FailOn)
}

func TestScanInput_WithEngines(t *testing.T) {
	input := ScanInput{
		Path:    "/project",
		Engines: []string{"gosec", "gitleaks"},
		Strict:  true,
	}

	assert.Equal(t, "/project", input.Path)
	assert.Len(t, input.Engines, 2)
	assert.Contains(t, input.Engines, "gosec")
	assert.Contains(t, input.Engines, "gitleaks")
	assert.True(t, input.Strict)
}

func TestScanResult_AllSeverities(t *testing.T) {
	result := &ScanResult{
		Status:        "completed",
		TotalCount:    10,
		CriticalCount: 2,
		HighCount:     3,
		MediumCount:   3,
		LowCount:      2,
		Duration:      "2.5s",
		Findings:      []FindingInfo{},
	}

	assert.Equal(t, 10, result.TotalCount)
	assert.Equal(t, 2, result.CriticalCount)
	assert.Equal(t, 3, result.HighCount)
	assert.Equal(t, 3, result.MediumCount)
	assert.Equal(t, 2, result.LowCount)
}

func TestPolicyCheckResult_WithMessages(t *testing.T) {
	result := &PolicyCheckResult{
		Decision:      "FAIL",
		FailThreshold: "HIGH",
		WarnThreshold: "MEDIUM",
		Violations:    5,
		Warnings:      3,
		Messages: []string{
			"Found 2 critical findings",
			"Found 3 high findings",
			"3 medium severity findings",
		},
	}

	assert.Equal(t, "FAIL", result.Decision)
	assert.Equal(t, 5, result.Violations)
	assert.Equal(t, 3, result.Warnings)
	assert.Len(t, result.Messages, 3)
}

func TestJoin_EdgeCases(t *testing.T) {
	// Empty separator
	result := join([]string{"a", "b"}, "")
	assert.Equal(t, "ab", result)

	// Long separator
	result = join([]string{"x", "y"}, " -> ")
	assert.Equal(t, "x -> y", result)
}

func TestServer_HandleConfigResource(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Version = "1"
	cfg.Policy.Threshold.FailOn = "CRITICAL"
	cfg.Policy.Threshold.WarnOn = "HIGH"
	cfg.Policy.BaselineMode = "warn"
	cfg.Engines.Gosec.Enabled = true
	cfg.Engines.Govulncheck.Enabled = true
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Baseline.Path = ".verdict/baseline.json"

	server := NewServer(cfg)

	content, err := server.handleConfigResource(nil, "verdict://config", nil)

	require.NoError(t, err)
	require.NotNil(t, content)
	assert.Equal(t, "verdict://config", content.URI)
	assert.Equal(t, "application/json", content.MimeType)
	assert.Contains(t, content.Text, `"version": "1"`)
	assert.Contains(t, content.Text, `"fail_on": "CRITICAL"`)
	assert.Contains(t, content.Text, `"warn_on": "HIGH"`)
}

func TestServer_HandleBaselineResource_NoBaseline(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Baseline.Path = "/nonexistent/baseline.json"

	server := NewServer(cfg)

	content, err := server.handleBaselineResource(nil, "verdict://baseline", nil)

	require.NoError(t, err)
	require.NotNil(t, content)
	assert.Equal(t, "verdict://baseline", content.URI)
	assert.Equal(t, "application/json", content.MimeType)
	assert.Contains(t, content.Text, `"entries": []`)
	assert.Contains(t, content.Text, `"count": 0`)
}

func TestServer_HandleBaselineResource_DefaultPath(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Baseline.Path = ""

	server := NewServer(cfg)

	content, err := server.handleBaselineResource(nil, "verdict://baseline", nil)

	require.NoError(t, err)
	require.NotNil(t, content)
	assert.Contains(t, content.Text, `"entries":`)
}

func TestServer_HandleEnginesResource(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Engines.Govulncheck.Enabled = true
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false

	server := NewServer(cfg)

	content, err := server.handleEnginesResource(nil, "verdict://engines", nil)

	require.NoError(t, err)
	require.NotNil(t, content)
	assert.Equal(t, "verdict://engines", content.URI)
	assert.Equal(t, "application/json", content.MimeType)
	assert.Contains(t, content.Text, `"engines": [`)
	assert.Contains(t, content.Text, `"id": "gosec"`)
	assert.Contains(t, content.Text, `"id": "govulncheck"`)
	assert.Contains(t, content.Text, `"id": "gitleaks"`)
	assert.Contains(t, content.Text, `"id": "cyclonedx-gomod"`)
}

func TestServer_RunScan_NoEngines(t *testing.T) {
	// Test that runScan errors when no engines are available
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false

	server := NewServer(cfg)

	input := ScanInput{
		Path: "",
	}

	_, err := server.runScan(nil, input, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no engines available")
}

func TestServer_RunScan_WithSpecifiedEngines(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false

	server := NewServer(cfg)

	// Specify engines via input - parsed from string list
	input := ScanInput{
		Path:    ".",
		Engines: []string{"gosec", "govulncheck", "gitleaks"},
	}

	// Will either error or succeed depending on engine availability
	_, err := server.runScan(nil, input, nil)
	// Just verify it doesn't panic, error is expected if engines unavailable
	_ = err
}

func TestServer_RunScan_StrictModeError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false

	server := NewServer(cfg)

	input := ScanInput{
		Path:   ".",
		Strict: true,
	}

	_, err := server.runScan(nil, input, nil)

	// With no engines, should fail
	assert.Error(t, err)
}

func TestServer_HandleBaselineAdd_Error(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false

	server := NewServer(cfg)

	tmpDir := t.TempDir()
	input := BaselineAddInput{
		Path:   tmpDir,
		Output: tmpDir + "/baseline.json",
		Reason: "test reason",
	}

	// With no engines available, should fail
	_, err := server.handleBaselineAdd(nil, input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan failed")
}

func TestServer_HandlePolicyCheck_Error(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false

	server := NewServer(cfg)

	tmpDir := t.TempDir()
	input := PolicyCheckInput{
		Path: tmpDir,
	}

	// With no engines available, should fail
	_, err := server.handlePolicyCheck(nil, input)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan failed")
}
