package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/internal/testing/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnginesCmd_Properties(t *testing.T) {
	assert.NotNil(t, enginesCmd)
	assert.Equal(t, "engines", enginesCmd.Use)
	assert.Contains(t, enginesCmd.Short, "status")
}

func TestEnginesCmd_Flags(t *testing.T) {
	assert.NotNil(t, enginesCmd.Flags().Lookup("json"))
	assert.NotNil(t, enginesCmd.Flags().Lookup("check"))
}

func TestCapabilityLabel_SAST(t *testing.T) {
	result := capabilityLabel(ports.CapabilitySAST)
	assert.Equal(t, "Static Analysis", result)
}

func TestCapabilityLabel_Vuln(t *testing.T) {
	result := capabilityLabel(ports.CapabilityVuln)
	assert.Equal(t, "Vulnerability", result)
}

func TestCapabilityLabel_Secrets(t *testing.T) {
	result := capabilityLabel(ports.CapabilitySecrets)
	assert.Equal(t, "Secrets", result)
}

func TestCapabilityLabel_SBOM(t *testing.T) {
	result := capabilityLabel(ports.CapabilitySBOM)
	assert.Equal(t, "SBOM", result)
}

func TestCapabilityLabel_Unknown(t *testing.T) {
	result := capabilityLabel(ports.Capability("unknown"))
	assert.Equal(t, "unknown", result)
}

func TestRunEngines_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := runEngines(enginesCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestRunEngines_Success(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
engines:
  gosec:
    enabled: true
  govulncheck:
    enabled: true
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldJSONOutput := enginesJSONOutput
	defer func() {
		cfgFile = oldCfgFile
		enginesJSONOutput = oldJSONOutput
	}()

	cfgFile = configPath
	enginesJSONOutput = false

	// This will run and produce output to stdout
	err := runEngines(enginesCmd, []string{})

	assert.NoError(t, err)
}

func TestRunEngines_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
engines:
  gosec:
    enabled: true
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldJSONOutput := enginesJSONOutput
	defer func() {
		cfgFile = oldCfgFile
		enginesJSONOutput = oldJSONOutput
	}()

	cfgFile = configPath
	enginesJSONOutput = true

	err := runEngines(enginesCmd, []string{})

	assert.NoError(t, err)
}

func TestOutputEnginesJSON(t *testing.T) {
	statuses := []engines.EngineStatus{
		{
			Info: ports.EngineInfo{
				ID:          ports.EngineGosec,
				Name:        "Gosec",
				Description: "Go security checker",
				InstallCmd:  "go install github.com/securego/gosec/v2/cmd/gosec@latest",
				Homepage:    "https://github.com/securego/gosec",
				Capability:  ports.CapabilitySAST,
			},
			Available: true,
			Version:   "2.21.0",
			Enabled:   true,
		},
		{
			Info: ports.EngineInfo{
				ID:          ports.EngineGitleaks,
				Name:        "Gitleaks",
				Description: "Secrets scanner",
				InstallCmd:  "go install github.com/gitleaks/gitleaks/v8@latest",
				Homepage:    "https://github.com/gitleaks/gitleaks",
				Capability:  ports.CapabilitySecrets,
			},
			Available: false,
			Version:   "",
			Enabled:   true,
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputEnginesJSON(statuses)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, r)
	require.NoError(t, copyErr)
	output := buf.String()

	assert.NoError(t, err)
	assert.Contains(t, output, "gosec")
	assert.Contains(t, output, "Gosec")
	assert.Contains(t, output, "gitleaks")
	assert.Contains(t, output, "available")
}

func TestOutputEnginesTable_AllAvailable(t *testing.T) {
	statuses := []engines.EngineStatus{
		{
			Info: ports.EngineInfo{
				ID:          ports.EngineGosec,
				Name:        "Gosec",
				Description: "Go security checker",
				InstallCmd:  "go install github.com/securego/gosec/v2/cmd/gosec@latest",
				Homepage:    "https://github.com/securego/gosec",
				Capability:  ports.CapabilitySAST,
			},
			Available: true,
			Version:   "2.21.0",
			Enabled:   true,
		},
	}

	// Table output goes to stdout
	err := outputEnginesTable(statuses, false)
	assert.NoError(t, err)
}

func TestOutputEnginesTable_SomeMissing(t *testing.T) {
	statuses := []engines.EngineStatus{
		{
			Info: ports.EngineInfo{
				ID:          ports.EngineGosec,
				Name:        "Gosec",
				Description: "Go security checker",
				InstallCmd:  "go install github.com/securego/gosec/v2/cmd/gosec@latest",
				Homepage:    "https://github.com/securego/gosec",
				Capability:  ports.CapabilitySAST,
			},
			Available: true,
			Version:   "2.21.0",
			Enabled:   true,
		},
		{
			Info: ports.EngineInfo{
				ID:          ports.EngineGitleaks,
				Name:        "Gitleaks",
				Description: "Secrets scanner",
				InstallCmd:  "go install github.com/gitleaks/gitleaks/v8@latest",
				Homepage:    "https://github.com/gitleaks/gitleaks",
				Capability:  ports.CapabilitySecrets,
			},
			Available: false,
			Version:   "",
			Enabled:   true,
		},
	}

	err := outputEnginesTable(statuses, false)
	assert.NoError(t, err)
}

func TestOutputEnginesTable_Disabled(t *testing.T) {
	statuses := []engines.EngineStatus{
		{
			Info: ports.EngineInfo{
				ID:          ports.EngineGosec,
				Name:        "Gosec",
				Description: "Go security checker",
				InstallCmd:  "go install github.com/securego/gosec/v2/cmd/gosec@latest",
				Homepage:    "https://github.com/securego/gosec",
				Capability:  ports.CapabilitySAST,
			},
			Available: false,
			Version:   "",
			Enabled:   false, // Disabled, so won't show as missing
		},
	}

	err := outputEnginesTable(statuses, false)
	assert.NoError(t, err)
}

func TestOutputEnginesTable_UnknownVersion(t *testing.T) {
	statuses := []engines.EngineStatus{
		{
			Info: ports.EngineInfo{
				ID:          ports.EngineGosec,
				Name:        "Gosec",
				Description: "Go security checker",
				InstallCmd:  "go install github.com/securego/gosec/v2/cmd/gosec@latest",
				Homepage:    "https://github.com/securego/gosec",
				Capability:  ports.CapabilitySAST,
			},
			Available: true,
			Version:   "unknown",
			Enabled:   true,
		},
	}

	err := outputEnginesTable(statuses, false)
	assert.NoError(t, err)
}

func TestOutputEnginesTable_EmptyVersion(t *testing.T) {
	statuses := []engines.EngineStatus{
		{
			Info: ports.EngineInfo{
				ID:          ports.EngineGosec,
				Name:        "Gosec",
				Description: "Go security checker",
				InstallCmd:  "go install github.com/securego/gosec/v2/cmd/gosec@latest",
				Homepage:    "https://github.com/securego/gosec",
				Capability:  ports.CapabilitySAST,
			},
			Available: true,
			Version:   "",
			Enabled:   true,
		},
	}

	err := outputEnginesTable(statuses, false)
	assert.NoError(t, err)
}

func TestWarnMissingEngines_NoMissing(t *testing.T) {
	registry := engines.NewRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.IsAvailableValue = true
	registry.Register(mockEngine)

	cfg := ports.Config{
		Engines: map[ports.EngineID]ports.EngineConfig{
			ports.EngineGosec: {Enabled: true},
		},
	}

	warned := WarnMissingEngines(registry, cfg)
	assert.False(t, warned)
}

func TestWarnMissingEngines_WithMissing(t *testing.T) {
	registry := engines.NewRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.IsAvailableValue = false
	mockEngine.InfoValue = ports.EngineInfo{
		ID:         ports.EngineGosec,
		Name:       "Gosec",
		InstallCmd: "go install github.com/securego/gosec/v2/cmd/gosec@latest",
	}
	registry.Register(mockEngine)

	cfg := ports.Config{
		Engines: map[ports.EngineID]ports.EngineConfig{
			ports.EngineGosec: {Enabled: true},
		},
	}

	warned := WarnMissingEngines(registry, cfg)
	assert.True(t, warned)
}

func TestWarnMissingEngines_MissingButDisabled(t *testing.T) {
	registry := engines.NewRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.IsAvailableValue = false
	registry.Register(mockEngine)

	cfg := ports.Config{
		Engines: map[ports.EngineID]ports.EngineConfig{
			ports.EngineGosec: {Enabled: false}, // Disabled, so no warning
		},
	}

	warned := WarnMissingEngines(registry, cfg)
	assert.False(t, warned)
}

func TestWarnMissingEngines_NotInConfig(t *testing.T) {
	registry := engines.NewRegistry()
	mockEngine := mocks.NewMockEngine(ports.EngineGosec)
	mockEngine.IsAvailableValue = false
	mockEngine.InfoValue = ports.EngineInfo{
		ID:         ports.EngineGosec,
		Name:       "Gosec",
		InstallCmd: "go install github.com/securego/gosec/v2/cmd/gosec@latest",
	}
	registry.Register(mockEngine)

	// Engine not in config defaults to enabled, so should warn
	cfg := ports.Config{
		Engines: map[ports.EngineID]ports.EngineConfig{},
	}

	warned := WarnMissingEngines(registry, cfg)
	assert.True(t, warned)
}

func TestWarnMissingEngines_MultipleEngines(t *testing.T) {
	registry := engines.NewRegistry()

	// Available engine
	availableEngine := mocks.NewMockEngine(ports.EngineGosec)
	availableEngine.IsAvailableValue = true
	registry.Register(availableEngine)

	// Missing engine
	missingEngine := mocks.NewMockEngine(ports.EngineGitleaks)
	missingEngine.IsAvailableValue = false
	missingEngine.InfoValue = ports.EngineInfo{
		ID:         ports.EngineGitleaks,
		Name:       "Gitleaks",
		InstallCmd: "go install github.com/gitleaks/gitleaks/v8@latest",
	}
	registry.Register(missingEngine)

	cfg := ports.Config{
		Engines: map[ports.EngineID]ports.EngineConfig{
			ports.EngineGosec:    {Enabled: true},
			ports.EngineGitleaks: {Enabled: true},
		},
	}

	warned := WarnMissingEngines(registry, cfg)
	assert.True(t, warned)
}

func TestEngineStatusJSON_Struct(t *testing.T) {
	// Test that the struct can be instantiated
	status := engineStatusJSON{
		ID:          "gosec",
		Name:        "Gosec",
		Description: "Go security checker",
		Capability:  "sast",
		Available:   true,
		Version:     "2.21.0",
		Enabled:     true,
		InstallCmd:  "go install github.com/securego/gosec/v2/cmd/gosec@latest",
		Homepage:    "https://github.com/securego/gosec",
	}

	assert.Equal(t, "gosec", status.ID)
	assert.Equal(t, "Gosec", status.Name)
	assert.True(t, status.Available)
	assert.True(t, status.Enabled)
}

func TestCapabilityLabel_AllCases(t *testing.T) {
	tests := []struct {
		cap      ports.Capability
		expected string
	}{
		{ports.CapabilitySAST, "Static Analysis"},
		{ports.CapabilityVuln, "Vulnerability"},
		{ports.CapabilitySecrets, "Secrets"},
		{ports.CapabilitySBOM, "SBOM"},
		{ports.Capability("custom"), "custom"},
		{ports.Capability(""), ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.cap), func(t *testing.T) {
			result := capabilityLabel(tt.cap)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOutputEnginesJSON_Empty(t *testing.T) {
	statuses := []engines.EngineStatus{}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputEnginesJSON(statuses)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, r)
	require.NoError(t, copyErr)
	output := buf.String()

	assert.NoError(t, err)
	assert.Contains(t, output, "[]")
}

func TestOutputEnginesTable_Empty(t *testing.T) {
	statuses := []engines.EngineStatus{}

	err := outputEnginesTable(statuses, false)
	assert.NoError(t, err)
}

func TestEnginesCmd_HasRunE(t *testing.T) {
	assert.NotNil(t, enginesCmd.RunE)
}

func TestEnginesCmd_Long(t *testing.T) {
	assert.Contains(t, enginesCmd.Long, "status")
	assert.Contains(t, enginesCmd.Long, "engines")
}
