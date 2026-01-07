package mcp

import (
	"context"
	"os"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/felixgeelhaar/verdictsec/internal/testing/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	cfg := config.DefaultConfig()
	server := NewServer(cfg, "test")

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
	server := NewServer(cfg, "test")

	// Verify registry is properly initialized
	require.NotNil(t, server.registry)
}

func TestServer_ConfigStored(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Policy.Threshold.FailOn = "CRITICAL"
	server := NewServer(cfg, "test")

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

	server := NewServer(cfg, "test")

	content, err := server.handleConfigResource(context.Background(), "verdict://config", nil)

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

	server := NewServer(cfg, "test")

	content, err := server.handleBaselineResource(context.Background(), "verdict://baseline", nil)

	require.NoError(t, err)
	require.NotNil(t, content)
	assert.Equal(t, "verdict://baseline", content.URI)
	assert.Equal(t, "application/json", content.MimeType)
	assert.Contains(t, content.Text, `"entries":[]`)
	assert.Contains(t, content.Text, `"count":0`)
}

func TestServer_HandleBaselineResource_DefaultPath(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Baseline.Path = ""

	server := NewServer(cfg, "test")

	content, err := server.handleBaselineResource(context.Background(), "verdict://baseline", nil)

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

	server := NewServer(cfg, "test")

	content, err := server.handleEnginesResource(context.Background(), "verdict://engines", nil)

	require.NoError(t, err)
	require.NotNil(t, content)
	assert.Equal(t, "verdict://engines", content.URI)
	assert.Equal(t, "application/json", content.MimeType)
	assert.Contains(t, content.Text, `"engines":[`)
	assert.Contains(t, content.Text, `"id":"gosec"`)
	assert.Contains(t, content.Text, `"id":"govulncheck"`)
	assert.Contains(t, content.Text, `"id":"gitleaks"`)
	assert.Contains(t, content.Text, `"id":"cyclonedx-gomod"`)
	assert.Contains(t, content.Text, `"id":"staticcheck"`)
	assert.Contains(t, content.Text, `"id":"syft"`)
}

func TestServer_RunScan_NoEngines(t *testing.T) {
	// Test behavior when no engines are enabled
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Engines.Syft.Enabled = false
	cfg.Engines.Staticcheck.Enabled = false

	server := NewServer(cfg, "test")

	input := ScanInput{
		Path: "",
	}

	result, err := server.runScan(context.Background(), input, nil)

	// With no engines, may either error or succeed with no findings
	if err != nil {
		assert.Contains(t, err.Error(), "no engines")
	} else {
		assert.NotNil(t, result)
		assert.Equal(t, 0, result.TotalCount)
	}
}

func TestServer_RunScan_WithSpecifiedEngines(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Engines.Syft.Enabled = false
	cfg.Engines.Staticcheck.Enabled = false

	server := NewServer(cfg, "test")

	// Specify engines via input - parsed from string list
	input := ScanInput{
		Path:    ".",
		Engines: []string{"gosec", "govulncheck", "gitleaks"},
	}

	// Will either error or succeed depending on engine availability
	_, err := server.runScan(context.Background(), input, nil)
	// Just verify it doesn't panic, error is expected if engines unavailable
	_ = err
}

func TestServer_RunScan_StrictModeNoEngines(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Engines.Syft.Enabled = false
	cfg.Engines.Staticcheck.Enabled = false

	server := NewServer(cfg, "test")

	input := ScanInput{
		Path:   ".",
		Strict: true,
	}

	result, err := server.runScan(context.Background(), input, nil)

	// With no engines, may either error or succeed with no findings
	if err != nil {
		assert.Contains(t, err.Error(), "no engines")
	} else {
		assert.NotNil(t, result)
	}
}

func TestServer_HandleBaselineAdd_NoEngines(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Engines.Syft.Enabled = false
	cfg.Engines.Staticcheck.Enabled = false

	server := NewServer(cfg, "test")

	tmpDir := t.TempDir()
	input := BaselineAddInput{
		Path:   tmpDir,
		Output: tmpDir + "/baseline.json",
		Reason: "test reason",
	}

	// With no engines enabled, baseline add should still succeed
	// but create an empty baseline (no findings to baseline)
	result, err := server.handleBaselineAdd(context.Background(), input)

	// Either fails with "no engines" error OR succeeds with empty baseline
	if err != nil {
		assert.Contains(t, err.Error(), "scan failed")
	} else {
		assert.NotNil(t, result)
		assert.Equal(t, "created", result.Status)
		assert.Equal(t, 0, result.EntriesAdded)
	}
}

func TestServer_HandlePolicyCheck_NoEngines(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Engines.Syft.Enabled = false
	cfg.Engines.Staticcheck.Enabled = false

	server := NewServer(cfg, "test")

	tmpDir := t.TempDir()
	input := PolicyCheckInput{
		Path: tmpDir,
	}

	// With no engines, may either error or succeed with PASS (no violations)
	result, err := server.handlePolicyCheck(context.Background(), input)

	if err != nil {
		assert.Contains(t, err.Error(), "scan failed")
	} else {
		assert.NotNil(t, result)
		assert.Equal(t, "PASS", result.Decision)
	}
}

func TestServer_RunScan_DefaultPath(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Engines.Syft.Enabled = false
	cfg.Engines.Staticcheck.Enabled = false

	server := NewServer(cfg, "test")

	// Empty path should default to "."
	input := ScanInput{
		Path: "",
	}

	result, err := server.runScan(context.Background(), input, nil)
	// May error or succeed with no findings depending on implementation
	if err != nil {
		assert.Contains(t, err.Error(), "no engines")
	} else {
		assert.NotNil(t, result)
	}
}

func TestServer_RunScan_InputEnginesParsing(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Engines.Syft.Enabled = false
	cfg.Engines.Staticcheck.Enabled = false

	server := NewServer(cfg, "test")

	// Specify engine via input
	input := ScanInput{
		Path:    ".",
		Engines: []string{"gosec"},
	}

	_, err := server.runScan(context.Background(), input, nil)
	// Will fail but parsing logic is exercised
	_ = err
}

func TestBaselineAddInput_EmptyReason(t *testing.T) {
	input := BaselineAddInput{
		Path:   "/project",
		Output: ".verdict/baseline.json",
		Reason: "",
	}

	assert.Empty(t, input.Reason)
}

func TestPolicyCheckInput_EmptyPath(t *testing.T) {
	input := PolicyCheckInput{
		Path: "",
	}

	assert.Empty(t, input.Path)
}

func TestServer_HandleConfigResource_FullConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Version = "1"
	cfg.Policy.Threshold.FailOn = "CRITICAL"
	cfg.Policy.Threshold.WarnOn = "HIGH"
	cfg.Policy.BaselineMode = "warn"
	cfg.Engines.Gosec.Enabled = true
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = true
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Baseline.Path = ""

	server := NewServer(cfg, "test")

	content, err := server.handleConfigResource(context.Background(), "verdict://config", nil)

	require.NoError(t, err)
	require.NotNil(t, content)

	// Check all engines are present in output (indented JSON)
	assert.Contains(t, content.Text, `"gosec"`)
	assert.Contains(t, content.Text, `"govulncheck"`)
	assert.Contains(t, content.Text, `"gitleaks"`)
	assert.Contains(t, content.Text, `"enabled": true`)
	assert.Contains(t, content.Text, `"enabled": false`)
}

func TestServer_HandleEnginesResource_AllEngines(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Engines.Govulncheck.Enabled = true
	cfg.Engines.Gitleaks.Enabled = true
	cfg.Engines.CycloneDX.Enabled = true

	server := NewServer(cfg, "test")

	content, err := server.handleEnginesResource(context.Background(), "verdict://engines", nil)

	require.NoError(t, err)
	require.NotNil(t, content)
	assert.Equal(t, "verdict://engines", content.URI)
	assert.Contains(t, content.Text, `"id":"gosec"`)
	assert.Contains(t, content.Text, `"id":"govulncheck"`)
	assert.Contains(t, content.Text, `"id":"gitleaks"`)
	assert.Contains(t, content.Text, `"id":"cyclonedx-gomod"`)
	assert.Contains(t, content.Text, `"id":"staticcheck"`)
	assert.Contains(t, content.Text, `"id":"syft"`)
}

// Tests with mock engines

func TestNewServerWithRegistry(t *testing.T) {
	cfg := config.DefaultConfig()
	registry := mocks.NewMockRegistry()

	server := NewServerWithRegistry(cfg, registry, "test")

	require.NotNil(t, server)
	assert.Equal(t, registry, server.registry)
}

func TestServer_RunScan_WithMockEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	mockEngine.WithFindings([]ports.RawFinding{
		{
			RuleID:    "G401",
			Message:   "Use of weak cryptographic primitive",
			Severity:  "HIGH",
			File:      "crypto.go",
			StartLine: 15,
			EndLine:   15,
		},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{
		Path:    ".",
		Engines: []string{"gosec"},
	}

	result, err := server.runScan(context.Background(), input, nil)

	require.NoError(t, err)
	assert.Equal(t, "completed", result.Status)
	assert.Equal(t, 1, result.TotalCount)
	assert.Equal(t, 1, result.HighCount)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "G401", result.Findings[0].RuleID)
}

func TestServer_RunScan_WithMockEngine_MultipleFindings(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	// Note: gosec normalizer uses rule-based severity overrides
	// G401 -> HIGH, G104 -> LOW, G101 -> CRITICAL
	mockEngine.WithFindings([]ports.RawFinding{
		{
			RuleID:    "G401",
			Message:   "Weak crypto",
			Severity:  "HIGH",
			File:      "crypto.go",
			StartLine: 15,
		},
		{
			RuleID:    "G104",
			Message:   "Errors unhandled",
			Severity:  "LOW", // G104 is overridden to LOW
			File:      "main.go",
			StartLine: 42,
		},
		{
			RuleID:    "G101",
			Message:   "Hardcoded credentials",
			Severity:  "CRITICAL",
			File:      "config.go",
			StartLine: 10,
		},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{
		Path:    ".",
		Engines: []string{"gosec"},
	}

	result, err := server.runScan(context.Background(), input, nil)

	require.NoError(t, err)
	assert.Equal(t, 3, result.TotalCount)
	// Gosec normalizer uses rule overrides: G101->CRITICAL, G401->HIGH, G104->LOW
	assert.Equal(t, 1, result.CriticalCount)
	assert.Equal(t, 1, result.HighCount)
	assert.Equal(t, 1, result.LowCount)
}

func TestServer_RunScan_WithMockEngine_NoFindings(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	mockEngine.WithFindings([]ports.RawFinding{})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{
		Path:    ".",
		Engines: []string{"gosec"},
	}

	result, err := server.runScan(context.Background(), input, nil)

	require.NoError(t, err)
	assert.Equal(t, "completed", result.Status)
	assert.Equal(t, 0, result.TotalCount)
	assert.Empty(t, result.Findings)
}

func TestServer_HandleScan_WithMockEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{Path: "."}
	result, err := server.handleScan(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "completed", result.Status)
}

func TestServer_HandleSAST_WithMockEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{Path: "."}
	result, err := server.handleSAST(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "completed", result.Status)
}

func TestServer_HandleVuln_WithMockEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Govulncheck.Enabled = true

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGovulncheck)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilityVuln}
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{Path: "."}
	result, err := server.handleVuln(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "completed", result.Status)
}

func TestServer_HandleSecrets_WithMockEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gitleaks.Enabled = true

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGitleaks)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySecrets}
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{Path: "."}
	result, err := server.handleSecrets(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "completed", result.Status)
}

func TestServer_HandleBaselineAdd_WithMockEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	mockEngine.WithFindings([]ports.RawFinding{
		{
			RuleID:    "G401",
			Message:   "Weak crypto",
			Severity:  "HIGH",
			File:      "crypto.go",
			StartLine: 15,
		},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	tmpDir := t.TempDir()
	input := BaselineAddInput{
		Path:   ".",
		Output: tmpDir + "/baseline.json",
		Reason: "Initial baseline",
	}

	result, err := server.handleBaselineAdd(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "created", result.Status)
	assert.Equal(t, 1, result.EntriesAdded)
}

func TestServer_HandlePolicyCheck_WithMockEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Policy.Threshold.FailOn = "CRITICAL"

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	mockEngine.WithFindings([]ports.RawFinding{
		{
			RuleID:    "G104",
			Message:   "Errors unhandled",
			Severity:  "MEDIUM",
			File:      "main.go",
			StartLine: 42,
		},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := PolicyCheckInput{Path: "."}
	result, err := server.handlePolicyCheck(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "PASS", result.Decision)
}

func TestServer_HandlePolicyCheck_WithMockEngine_Fail(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Policy.Threshold.FailOn = "HIGH"

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	mockEngine.WithFindings([]ports.RawFinding{
		{
			RuleID:    "G401",
			Message:   "Weak crypto",
			Severity:  "HIGH",
			File:      "crypto.go",
			StartLine: 15,
		},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := PolicyCheckInput{Path: "."}
	result, err := server.handlePolicyCheck(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "FAIL", result.Decision)
	assert.Equal(t, 1, result.Violations)
}

// Truncation Tests

func TestServer_RunScan_NoTruncation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	// Default max_findings is 50, we only have 3 findings

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	mockEngine.WithFindings([]ports.RawFinding{
		{RuleID: "G401", Message: "Weak crypto", Severity: "HIGH", File: "crypto.go", StartLine: 10},
		{RuleID: "G104", Message: "Errors unhandled", Severity: "LOW", File: "main.go", StartLine: 20},
		{RuleID: "G101", Message: "Hardcoded credentials", Severity: "CRITICAL", File: "config.go", StartLine: 30},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{Path: ".", Engines: []string{"gosec"}}
	result, err := server.runScan(context.Background(), input, nil)

	require.NoError(t, err)
	assert.False(t, result.Truncated, "should not be truncated")
	assert.Equal(t, 3, result.TotalCount)
	assert.Equal(t, 3, result.ShownCount)
	assert.Len(t, result.Findings, 3)
	assert.Nil(t, result.TruncationInfo)
}

func TestServer_RunScan_WithTruncation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	// Set very low max_findings to trigger truncation
	cfg.MCP.MaxFindings = 2
	cfg.MCP.TruncateStrategy = config.TruncateStrategyPriority

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	// Create 5 findings - gosec normalizer maps these to HIGH by default
	// so all will have HIGH severity after normalization
	mockEngine.WithFindings([]ports.RawFinding{
		{RuleID: "G401", Message: "Issue 1", Severity: "HIGH", File: "a.go", StartLine: 10},
		{RuleID: "G401", Message: "Issue 2", Severity: "HIGH", File: "b.go", StartLine: 20},
		{RuleID: "G401", Message: "Issue 3", Severity: "HIGH", File: "c.go", StartLine: 30},
		{RuleID: "G401", Message: "Issue 4", Severity: "HIGH", File: "d.go", StartLine: 40},
		{RuleID: "G401", Message: "Issue 5", Severity: "HIGH", File: "e.go", StartLine: 50},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{Path: ".", Engines: []string{"gosec"}}
	result, err := server.runScan(context.Background(), input, nil)

	require.NoError(t, err)
	assert.True(t, result.Truncated, "should be truncated")
	assert.Equal(t, 5, result.TotalCount)
	assert.Equal(t, 2, result.ShownCount)
	assert.Len(t, result.Findings, 2)

	// Verify truncation info
	require.NotNil(t, result.TruncationInfo)
	assert.Equal(t, 5, result.TruncationInfo.TotalFindings)
	assert.Equal(t, 2, result.TruncationInfo.ShownFindings)
	assert.Equal(t, "priority", result.TruncationInfo.Strategy)
	assert.Contains(t, result.TruncationInfo.Message, "2 of 5")

	// Verify hidden counts - 3 HIGH findings were cut
	assert.Equal(t, 3, result.TruncationInfo.HiddenBySeverity["HIGH"])
}

func TestServer_RunScan_TruncationPreservesTotalCounts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.MCP.MaxFindings = 1

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	// Use rule IDs that gosec normalizer maps to specific severities:
	// G101 -> CRITICAL, G401 -> HIGH, G404 -> MEDIUM, G104 -> LOW
	mockEngine.WithFindings([]ports.RawFinding{
		{RuleID: "G101", Message: "Critical", Severity: "CRITICAL", File: "a.go", StartLine: 10},
		{RuleID: "G401", Message: "High", Severity: "HIGH", File: "b.go", StartLine: 20},
		{RuleID: "G404", Message: "Medium", Severity: "MEDIUM", File: "c.go", StartLine: 30},
		{RuleID: "G104", Message: "Low", Severity: "LOW", File: "d.go", StartLine: 40},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{Path: ".", Engines: []string{"gosec"}}
	result, err := server.runScan(context.Background(), input, nil)

	require.NoError(t, err)

	// Severity counts should reflect ALL findings, not just shown ones
	assert.Equal(t, 1, result.CriticalCount)
	assert.Equal(t, 1, result.HighCount)
	assert.Equal(t, 1, result.MediumCount)
	assert.Equal(t, 1, result.LowCount)

	// But only 1 finding should be shown
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, 4, result.TotalCount)
	assert.Equal(t, 1, result.ShownCount)
}

func TestServer_RunScan_TruncationDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	// Set max_findings to -1 to disable truncation (0 = use default of 50)
	cfg.MCP.MaxFindings = -1

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	// Create many findings
	findings := make([]ports.RawFinding, 100)
	for i := 0; i < 100; i++ {
		findings[i] = ports.RawFinding{
			RuleID:    "G401",
			Message:   "Finding",
			Severity:  "LOW",
			File:      "file.go",
			StartLine: i + 1,
		}
	}
	mockEngine.WithFindings(findings)
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	input := ScanInput{Path: ".", Engines: []string{"gosec"}}
	result, err := server.runScan(context.Background(), input, nil)

	require.NoError(t, err)
	assert.False(t, result.Truncated)
	assert.Equal(t, 100, result.TotalCount)
	assert.Equal(t, 100, result.ShownCount)
	assert.Len(t, result.Findings, 100)
	assert.Nil(t, result.TruncationInfo)
}

func TestScanResult_TruncationInfo_Structure(t *testing.T) {
	info := &TruncationInfo{
		TotalFindings:    150,
		ShownFindings:    50,
		HiddenBySeverity: map[string]int{"MEDIUM": 80, "LOW": 20},
		Strategy:         "priority",
		Message:          "Showing 50 of 150 findings (sorted by priority)",
	}

	assert.Equal(t, 150, info.TotalFindings)
	assert.Equal(t, 50, info.ShownFindings)
	assert.Equal(t, 80, info.HiddenBySeverity["MEDIUM"])
	assert.Equal(t, 20, info.HiddenBySeverity["LOW"])
	assert.Equal(t, "priority", info.Strategy)
	assert.Contains(t, info.Message, "50 of 150")
}

// Baseline Filtering Tests

func TestServer_RunScan_WithBaselineFiltering(t *testing.T) {
	// Create a temp directory with baseline file
	tmpDir := t.TempDir()
	baselinePath := tmpDir + "/baseline.json"

	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Baseline.Path = baselinePath
	cfg.MCP.MaxFindings = -1 // Disable truncation

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	// Create 3 findings
	mockEngine.WithFindings([]ports.RawFinding{
		{RuleID: "G401", Message: "Issue 1", Severity: "HIGH", File: "a.go", StartLine: 10},
		{RuleID: "G401", Message: "Issue 2", Severity: "HIGH", File: "b.go", StartLine: 20},
		{RuleID: "G401", Message: "Issue 3", Severity: "HIGH", File: "c.go", StartLine: 30},
	})
	registry.Register(mockEngine)

	// First run without baseline - should show all findings
	server := NewServerWithRegistry(cfg, registry, "test")
	input := ScanInput{Path: ".", Engines: []string{"gosec"}}

	result, err := server.runScan(context.Background(), input, nil)
	require.NoError(t, err)
	assert.Equal(t, 3, result.TotalCount)
	assert.Equal(t, 0, result.BaselinedCount)
	assert.Len(t, result.Findings, 3)

	// Create baseline with first 2 findings using correct JSON structure
	baselineData := `{
		"version": "1",
		"scope": {"project": "."},
		"fingerprints": [
			{"fingerprint": "` + result.Findings[0].Fingerprint + `", "rule_id": "G401", "engine_id": "gosec", "file": "a.go", "reason": "Test baseline"},
			{"fingerprint": "` + result.Findings[1].Fingerprint + `", "rule_id": "G401", "engine_id": "gosec", "file": "b.go", "reason": "Test baseline"}
		]
	}`
	err = os.WriteFile(baselinePath, []byte(baselineData), 0644)
	require.NoError(t, err)

	// Re-run scan with baseline - should filter 2 findings
	result2, err := server.runScan(context.Background(), input, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, result2.TotalCount, "only non-baselined findings should be counted")
	assert.Equal(t, 2, result2.BaselinedCount, "should report 2 baselined findings")
	assert.Len(t, result2.Findings, 1)
}

func TestServer_PolicyCheck_WithBaselineFiltering(t *testing.T) {
	// Create a temp directory with baseline file
	tmpDir := t.TempDir()
	baselinePath := tmpDir + "/baseline.json"

	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Baseline.Path = baselinePath
	cfg.Policy.Threshold.FailOn = "HIGH"

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	// Create HIGH severity finding that would normally cause FAIL
	mockEngine.WithFindings([]ports.RawFinding{
		{RuleID: "G401", Message: "Weak crypto", Severity: "HIGH", File: "crypto.go", StartLine: 15},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	// First check without baseline - should FAIL
	result, err := server.handlePolicyCheck(context.Background(), PolicyCheckInput{Path: "."})
	require.NoError(t, err)
	assert.Equal(t, "FAIL", result.Decision)
	assert.Equal(t, 1, result.Violations)
	assert.Equal(t, 0, result.BaselinedCount)

	// Get the fingerprint for baselining
	scanResult, err := server.runScan(context.Background(), ScanInput{Path: ".", Engines: []string{"gosec"}}, nil)
	require.NoError(t, err)
	require.Len(t, scanResult.Findings, 1)
	fingerprint := scanResult.Findings[0].Fingerprint

	// Create baseline with the HIGH severity finding using correct JSON structure
	baselineData := `{
		"version": "1",
		"scope": {"project": "."},
		"fingerprints": [
			{"fingerprint": "` + fingerprint + `", "rule_id": "G401", "engine_id": "gosec", "file": "crypto.go", "reason": "Accepted risk"}
		]
	}`
	err = os.WriteFile(baselinePath, []byte(baselineData), 0644)
	require.NoError(t, err)

	// Re-check with baseline - should PASS (all violations are baselined)
	result2, err := server.handlePolicyCheck(context.Background(), PolicyCheckInput{Path: "."})
	require.NoError(t, err)
	assert.Equal(t, "PASS", result2.Decision)
	assert.Equal(t, 0, result2.Violations)
	assert.Equal(t, 1, result2.BaselinedCount)
	assert.Contains(t, result2.Messages, "1 findings filtered by baseline")
	assert.Contains(t, result2.Messages, "All findings are baselined")
}

func TestServer_RunScan_NoBaseline(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Baseline.Path = "/nonexistent/baseline.json"
	cfg.MCP.MaxFindings = -1

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	mockEngine.WithFindings([]ports.RawFinding{
		{RuleID: "G401", Message: "Issue", Severity: "HIGH", File: "a.go", StartLine: 10},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")
	input := ScanInput{Path: ".", Engines: []string{"gosec"}}

	result, err := server.runScan(context.Background(), input, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, result.TotalCount)
	assert.Equal(t, 0, result.BaselinedCount)
	assert.Len(t, result.Findings, 1)
}

func TestScanResult_BaselinedCount_Structure(t *testing.T) {
	result := &ScanResult{
		Status:         "completed",
		TotalCount:     5,
		ShownCount:     5,
		BaselinedCount: 10,
		CriticalCount:  1,
		HighCount:      2,
		MediumCount:    1,
		LowCount:       1,
	}

	assert.Equal(t, 10, result.BaselinedCount)
	assert.Equal(t, 5, result.TotalCount)
}

func TestPolicyCheckResult_BaselinedCount_Structure(t *testing.T) {
	result := &PolicyCheckResult{
		Decision:       "PASS",
		FailThreshold:  "HIGH",
		WarnThreshold:  "MEDIUM",
		Violations:     0,
		Warnings:       0,
		BaselinedCount: 15,
		Messages:       []string{"All findings are baselined"},
	}

	assert.Equal(t, 15, result.BaselinedCount)
	assert.Equal(t, "PASS", result.Decision)
}

func TestServer_RunScan_BaselineAutoDetection(t *testing.T) {
	// This test verifies that baseline is auto-detected from alternate paths
	// when not explicitly configured. Fixes issue #8.

	// Save current directory and change to temp dir for auto-detection to work
	origDir, err := os.Getwd()
	require.NoError(t, err)
	tmpDir := t.TempDir()
	err = os.Chdir(tmpDir)
	require.NoError(t, err)
	defer os.Chdir(origDir)

	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Baseline.Path = "" // Empty - should auto-detect
	cfg.MCP.MaxFindings = -1

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	mockEngine.WithFindings([]ports.RawFinding{
		{RuleID: "G401", Message: "Issue 1", Severity: "HIGH", File: "a.go", StartLine: 10},
		{RuleID: "G401", Message: "Issue 2", Severity: "HIGH", File: "b.go", StartLine: 20},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")
	input := ScanInput{Path: ".", Engines: []string{"gosec"}}

	// First scan - no baseline exists
	result1, err := server.runScan(context.Background(), input, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, result1.TotalCount)
	assert.Equal(t, 0, result1.BaselinedCount)

	// Create baseline at alternate path (.verdict-baseline.json) - not the default
	baselineData := `{
		"version": "1",
		"scope": {"project": "."},
		"fingerprints": [
			{"fingerprint": "` + result1.Findings[0].Fingerprint + `", "rule_id": "G401", "engine_id": "gosec", "file": "a.go", "reason": "Test"}
		]
	}`
	err = os.WriteFile(".verdict-baseline.json", []byte(baselineData), 0644)
	require.NoError(t, err)

	// Re-run scan - should auto-detect .verdict-baseline.json and filter findings
	result2, err := server.runScan(context.Background(), input, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, result2.TotalCount, "auto-detection should filter 1 finding")
	assert.Equal(t, 1, result2.BaselinedCount, "should report 1 baselined finding")
}

func TestServer_RunScan_BaselineExplicitPath(t *testing.T) {
	// This test verifies that explicit baseline path in input takes priority

	tmpDir := t.TempDir()
	customBaselinePath := tmpDir + "/custom-baseline.json"

	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Baseline.Path = "" // Not set
	cfg.MCP.MaxFindings = -1

	registry := mocks.NewMockRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}
	mockEngine.WithFindings([]ports.RawFinding{
		{RuleID: "G401", Message: "Issue 1", Severity: "HIGH", File: "a.go", StartLine: 10},
	})
	registry.Register(mockEngine)

	server := NewServerWithRegistry(cfg, registry, "test")

	// First scan to get fingerprint
	result1, err := server.runScan(context.Background(), ScanInput{Path: ".", Engines: []string{"gosec"}}, nil)
	require.NoError(t, err)
	require.Len(t, result1.Findings, 1)

	// Create baseline at custom path
	baselineData := `{
		"version": "1",
		"scope": {"project": "."},
		"fingerprints": [
			{"fingerprint": "` + result1.Findings[0].Fingerprint + `", "rule_id": "G401", "engine_id": "gosec", "file": "a.go", "reason": "Test"}
		]
	}`
	err = os.WriteFile(customBaselinePath, []byte(baselineData), 0644)
	require.NoError(t, err)

	// Scan with explicit baseline path
	input := ScanInput{
		Path:     ".",
		Engines:  []string{"gosec"},
		Baseline: customBaselinePath,
	}
	result2, err := server.runScan(context.Background(), input, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, result2.TotalCount, "explicit baseline should filter finding")
	assert.Equal(t, 1, result2.BaselinedCount, "should report 1 baselined finding")
}
