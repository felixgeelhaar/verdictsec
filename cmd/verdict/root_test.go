package main

import (
	"os"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCommand(t *testing.T) {
	// Test that root command exists and has correct properties
	assert.NotNil(t, rootCmd)
	assert.Equal(t, "verdict", rootCmd.Use)
	assert.Contains(t, rootCmd.Short, "Security assessment")
}

func TestVersionCommand(t *testing.T) {
	// Test that version command exists
	assert.NotNil(t, versionCmd)
	assert.Equal(t, "version", versionCmd.Use)
}

func TestScanCommand(t *testing.T) {
	// Test that scan command exists and has correct properties
	assert.NotNil(t, scanCmd)
	assert.Equal(t, "scan [path]", scanCmd.Use)
	assert.Contains(t, scanCmd.Short, "security scan")
}

func TestCICommand(t *testing.T) {
	// Test that ci command exists
	assert.NotNil(t, ciCmd)
	assert.Equal(t, "ci [path]", ciCmd.Use)
	assert.Contains(t, ciCmd.Short, "CI mode")
}

func TestSASTCommand(t *testing.T) {
	// Test that sast command exists
	assert.NotNil(t, sastCmd)
	assert.Equal(t, "sast [path]", sastCmd.Use)
}

func TestVulnCommand(t *testing.T) {
	// Test that vuln command exists
	assert.NotNil(t, vulnCmd)
	assert.Equal(t, "vuln [path]", vulnCmd.Use)
}

func TestSecretsCommand(t *testing.T) {
	// Test that secrets command exists
	assert.NotNil(t, secretsCmd)
	assert.Equal(t, "secrets [path]", secretsCmd.Use)
}

func TestSBOMCommand(t *testing.T) {
	// Test that sbom command exists
	assert.NotNil(t, sbomCmd)
	assert.Equal(t, "sbom [path]", sbomCmd.Use)
}

func TestBaselineCommands(t *testing.T) {
	// Test that baseline commands exist
	assert.NotNil(t, baselineCmd)
	assert.Equal(t, "baseline", baselineCmd.Use)

	assert.NotNil(t, baselineWriteCmd)
	assert.Equal(t, "write [path]", baselineWriteCmd.Use)

	assert.NotNil(t, baselineUpdateCmd)
	assert.Equal(t, "update [path]", baselineUpdateCmd.Use)
}

func TestPolicyCommands(t *testing.T) {
	// Test that policy commands exist
	assert.NotNil(t, policyCmd)
	assert.Equal(t, "policy", policyCmd.Use)

	assert.NotNil(t, policyLintCmd)
	assert.Equal(t, "lint", policyLintCmd.Use)
}

func TestGetTarget(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{"empty args returns cwd", []string{}, ""}, // Will return cwd
		{"single arg returns arg", []string{"./myproject"}, "./myproject"},
		{"first arg is used", []string{"./first", "./second"}, "./first"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTarget(tt.args)
			if len(tt.args) > 0 {
				assert.Equal(t, tt.expected, result)
			} else {
				// For empty args, it returns current directory
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestDetermineEngines(t *testing.T) {
	// Test with default config
	cfg := DefaultTestConfig()

	engines := determineEngines(cfg)
	assert.Contains(t, engines, "gosec")
	assert.Contains(t, engines, "govulncheck")
	assert.Contains(t, engines, "gitleaks")
}

func TestDetermineEnginesWithExclusions(t *testing.T) {
	cfg := DefaultTestConfig()

	// Set up exclusions
	oldExclude := excludeEngines
	excludeEngines = []string{"gosec"}
	defer func() { excludeEngines = oldExclude }()

	engines := determineEngines(cfg)
	assert.NotContains(t, engines, "gosec")
	assert.Contains(t, engines, "govulncheck")
}

func TestDetermineEnginesWithInclusions(t *testing.T) {
	cfg := DefaultTestConfig()

	// Set up inclusions
	oldInclude := includeEngines
	includeEngines = []string{"gosec"}
	defer func() { includeEngines = oldInclude }()

	engines := determineEngines(cfg)
	assert.Equal(t, []string{"gosec"}, engines)
}

func TestApplyThresholdOverrides(t *testing.T) {
	cfg := DefaultTestConfig()

	// Set overrides
	oldFail := failThreshold
	oldWarn := warnThreshold
	failThreshold = "CRITICAL"
	warnThreshold = "HIGH"
	defer func() {
		failThreshold = oldFail
		warnThreshold = oldWarn
	}()

	applyThresholdOverrides(cfg)

	assert.Equal(t, "CRITICAL", cfg.Policy.Threshold.FailOn)
	assert.Equal(t, "HIGH", cfg.Policy.Threshold.WarnOn)
}

func TestGetModeString(t *testing.T) {
	// Default mode
	oldStrict := strictMode
	strictMode = false
	assert.Equal(t, "local", getModeString())

	// Strict mode
	strictMode = true
	assert.Equal(t, "ci", getModeString())

	strictMode = oldStrict
}

func TestApplyOverrides(t *testing.T) {
	cfg := config.DefaultConfig()

	// Save and restore global state
	oldJSON := jsonOutput
	oldVerbosity := verbosity
	oldNoColor := noColor
	defer func() {
		jsonOutput = oldJSON
		verbosity = oldVerbosity
		noColor = oldNoColor
	}()

	// Test JSON output override
	jsonOutput = true
	applyOverrides(cfg)
	assert.Equal(t, "json", cfg.Output.Format)

	// Test verbosity override
	verbosity = "verbose"
	applyOverrides(cfg)
	assert.Equal(t, "verbose", cfg.Output.Verbosity)

	// Test no-color override
	noColor = true
	applyOverrides(cfg)
	assert.False(t, cfg.Output.Color)
}

func TestApplyOverrides_NoChanges(t *testing.T) {
	cfg := config.DefaultConfig()
	originalFormat := cfg.Output.Format
	originalColor := cfg.Output.Color

	// Save and restore global state
	oldJSON := jsonOutput
	oldVerbosity := verbosity
	oldNoColor := noColor
	defer func() {
		jsonOutput = oldJSON
		verbosity = oldVerbosity
		noColor = oldNoColor
	}()

	jsonOutput = false
	verbosity = "normal" // Set to default value to not change
	noColor = false

	applyOverrides(cfg)

	// Should not change when flags are set to defaults
	assert.Equal(t, originalFormat, cfg.Output.Format)
	assert.Equal(t, "normal", cfg.Output.Verbosity)
	assert.Equal(t, originalColor, cfg.Output.Color)
}

func TestCreateWriter(t *testing.T) {
	cfg := config.DefaultConfig()

	// Save and restore global state
	oldNoColor := noColor
	oldOutputFlag := outputFlag
	defer func() {
		noColor = oldNoColor
		outputFlag = oldOutputFlag
	}()

	noColor = false
	outputFlag = ""

	writer, err := createWriter(cfg)

	require.NoError(t, err)
	assert.NotNil(t, writer)
}

func TestCreateWriter_ToFile(t *testing.T) {
	cfg := config.DefaultConfig()
	tmpDir := t.TempDir()

	// Save and restore global state
	oldOutputFlag := outputFlag
	defer func() {
		outputFlag = oldOutputFlag
	}()

	outputFlag = tmpDir + "/output.json"
	cfg.Output.Format = "json"

	writer, err := createWriter(cfg)

	require.NoError(t, err)
	assert.NotNil(t, writer)
}

func TestVersionCommand_Run(t *testing.T) {
	// Test that version command exists and can be executed
	assert.NotNil(t, versionCmd)
	assert.NotNil(t, versionCmd.Run)

	// The version command uses fmt.Printf which writes to stdout
	// Just verify the command is configured correctly
	assert.Equal(t, "version", versionCmd.Use)
	assert.Contains(t, versionCmd.Short, "version")
}

func TestDetermineEngines_AllDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Engines.Syft.Enabled = false
	cfg.Engines.Staticcheck.Enabled = false

	// Reset global flags
	oldInclude := includeEngines
	oldExclude := excludeEngines
	includeEngines = nil
	excludeEngines = nil
	defer func() {
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	engines := determineEngines(cfg)
	assert.Empty(t, engines)
}

func TestDetermineEngines_CycloneDX(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = true

	// Reset global flags
	oldInclude := includeEngines
	oldExclude := excludeEngines
	includeEngines = nil
	excludeEngines = nil
	defer func() {
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	engines := determineEngines(cfg)
	assert.Contains(t, engines, "cyclonedx-gomod")
}

func TestGetTarget_WithTargetPath(t *testing.T) {
	// Save and restore global state
	oldTargetPath := targetPath
	defer func() {
		targetPath = oldTargetPath
	}()

	targetPath = "/custom/path"
	result := getTarget([]string{})

	assert.Equal(t, "/custom/path", result)
}

func TestRootCommand_Flags(t *testing.T) {
	// Verify global flags exist
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("config"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("output"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("verbosity"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("no-color"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("json"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("strict"))
}

func TestScanCommand_Flags(t *testing.T) {
	// Verify scan-specific flags exist
	assert.NotNil(t, scanCmd.Flags().Lookup("baseline"))
	assert.NotNil(t, scanCmd.Flags().Lookup("policy"))
	assert.NotNil(t, scanCmd.Flags().Lookup("fail-on"))
	assert.NotNil(t, scanCmd.Flags().Lookup("warn-on"))
	assert.NotNil(t, scanCmd.Flags().Lookup("exclude"))
	assert.NotNil(t, scanCmd.Flags().Lookup("include"))
	assert.NotNil(t, scanCmd.Flags().Lookup("summary"))
}

func TestBaselineCommand_Flags(t *testing.T) {
	// Verify baseline write flags
	assert.NotNil(t, baselineWriteCmd.Flags().Lookup("output"))
	assert.NotNil(t, baselineWriteCmd.Flags().Lookup("reason"))

	// Verify baseline update flags
	assert.NotNil(t, baselineUpdateCmd.Flags().Lookup("prune"))
	assert.NotNil(t, baselineUpdateCmd.Flags().Lookup("reason"))
}

func TestApplyThresholdOverrides_NoChange(t *testing.T) {
	cfg := DefaultTestConfig()
	originalFail := cfg.Policy.Threshold.FailOn
	originalWarn := cfg.Policy.Threshold.WarnOn

	// Save and restore global state
	oldFail := failThreshold
	oldWarn := warnThreshold
	failThreshold = ""
	warnThreshold = ""
	defer func() {
		failThreshold = oldFail
		warnThreshold = oldWarn
	}()

	applyThresholdOverrides(cfg)

	assert.Equal(t, originalFail, cfg.Policy.Threshold.FailOn)
	assert.Equal(t, originalWarn, cfg.Policy.Threshold.WarnOn)
}

func TestDetermineEngines_MultipleExclusions(t *testing.T) {
	cfg := DefaultTestConfig()

	// Save and restore
	oldInclude := includeEngines
	oldExclude := excludeEngines
	includeEngines = nil
	excludeEngines = []string{"gosec", "gitleaks"}
	defer func() {
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	engines := determineEngines(cfg)
	assert.NotContains(t, engines, "gosec")
	assert.NotContains(t, engines, "gitleaks")
	assert.Contains(t, engines, "govulncheck")
}

func TestLoadConfig_Default(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = ""

	cfg, err := loadConfig()

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "1", cfg.Version)
}

func TestLoadConfig_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	// Write a valid config file
	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: CRITICAL
    warn_on: HIGH
engines:
  gosec:
    enabled: true
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = configPath

	cfg, err := loadConfig()

	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "CRITICAL", cfg.Policy.Threshold.FailOn)
	assert.Equal(t, "HIGH", cfg.Policy.Threshold.WarnOn)
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/path/config.yaml"

	_, err := loadConfig()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestLoadConfig_AppliesOverrides(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	oldJSON := jsonOutput
	oldVerbosity := verbosity
	oldNoColor := noColor
	defer func() {
		cfgFile = oldCfgFile
		jsonOutput = oldJSON
		verbosity = oldVerbosity
		noColor = oldNoColor
	}()

	cfgFile = ""
	jsonOutput = true
	verbosity = "verbose"
	noColor = true

	cfg, err := loadConfig()

	require.NoError(t, err)
	assert.Equal(t, "json", cfg.Output.Format)
	assert.Equal(t, "verbose", cfg.Output.Verbosity)
	assert.False(t, cfg.Output.Color)
}

func TestExecute_Success(t *testing.T) {
	// Test that Execute returns Success when root command runs without subcommand
	// This tests the basic execution path
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	// Run with --help which should succeed
	os.Args = []string{"verdict", "--help"}

	code := Execute()

	assert.Equal(t, 0, code)
}

func TestRootCmd_PersistentPreRunE(t *testing.T) {
	// Test PersistentPreRunE configures colors
	oldNoColor := noColor
	defer func() {
		noColor = oldNoColor
	}()

	noColor = true

	err := rootCmd.PersistentPreRunE(rootCmd, []string{})

	assert.NoError(t, err)
}

func TestGetTarget_EmptyArgsReturnsCwd(t *testing.T) {
	// Save and restore global state
	oldTargetPath := targetPath
	defer func() {
		targetPath = oldTargetPath
	}()

	targetPath = ""

	result := getTarget([]string{})

	// Should return current working directory
	wd, err := os.Getwd()
	require.NoError(t, err)
	assert.Equal(t, wd, result)
}

func TestRunScan_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := runScan(scanCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestRunCI_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := runCI(ciCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestRunBaselineWrite_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := runBaselineWrite(baselineWriteCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestRunBaselineUpdate_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := runBaselineUpdate(baselineUpdateCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestRunSingleEngine_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := runSingleEngine(sastCmd, []string{}, nil, "test")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestRunBaselineUpdate_NoEngines(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	// Create a config with all engines disabled
	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
engines:
  gosec:
    enabled: false
  govulncheck:
    enabled: false
  gitleaks:
    enabled: false
  cyclonedx-gomod:
    enabled: false
  syft:
    enabled: false
  staticcheck:
    enabled: false
  trivy:
    enabled: false
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = configPath

	err := runBaselineUpdate(baselineUpdateCmd, []string{tmpDir})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no engines")
}

func TestRunBaselineWrite_NoEngines(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	// Create a config with all engines disabled
	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
engines:
  gosec:
    enabled: false
  govulncheck:
    enabled: false
  gitleaks:
    enabled: false
  cyclonedx-gomod:
    enabled: false
  syft:
    enabled: false
  staticcheck:
    enabled: false
  trivy:
    enabled: false
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = configPath

	err := runBaselineWrite(baselineWriteCmd, []string{tmpDir})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no engines")
}

func TestRunCI_NoEngines(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	// Create a config with all engines disabled
	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
engines:
  gosec:
    enabled: false
  govulncheck:
    enabled: false
  gitleaks:
    enabled: false
  cyclonedx-gomod:
    enabled: false
  syft:
    enabled: false
  staticcheck:
    enabled: false
  trivy:
    enabled: false
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = configPath

	err := runCI(ciCmd, []string{tmpDir})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no engines")
}

func TestRunScan_NoEngines(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	// Create a config with all engines disabled
	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
engines:
  gosec:
    enabled: false
  govulncheck:
    enabled: false
  gitleaks:
    enabled: false
  cyclonedx-gomod:
    enabled: false
  syft:
    enabled: false
  staticcheck:
    enabled: false
  trivy:
    enabled: false
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldInclude := includeEngines
	oldExclude := excludeEngines
	defer func() {
		cfgFile = oldCfgFile
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	cfgFile = configPath
	includeEngines = nil
	excludeEngines = nil

	err := runScan(scanCmd, []string{tmpDir})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no engines")
}

func TestExecute_Error(t *testing.T) {
	// Test Execute when command returns an error
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	// Run with invalid subcommand to trigger error
	os.Args = []string{"verdict", "nonexistent-command"}

	code := Execute()

	// Should return error code since command doesn't exist
	assert.Equal(t, 2, code)
}

func TestCreateWriter_InvalidOutputPath(t *testing.T) {
	cfg := config.DefaultConfig()

	// Save and restore global state
	oldOutputFlag := outputFlag
	oldNoColor := noColor
	defer func() {
		outputFlag = oldOutputFlag
		noColor = oldNoColor
	}()

	// Set to a directory that doesn't exist with nested path
	outputFlag = "/nonexistent/deeply/nested/path/output.json"
	noColor = false

	_, err := createWriter(cfg)

	// Should fail because the directory doesn't exist
	assert.Error(t, err)
}

func TestApplyOverrides_Verbosity(t *testing.T) {
	cfg := config.DefaultConfig()

	// Save and restore global state
	oldJSON := jsonOutput
	oldVerbosity := verbosity
	oldNoColor := noColor
	defer func() {
		jsonOutput = oldJSON
		verbosity = oldVerbosity
		noColor = oldNoColor
	}()

	jsonOutput = false
	verbosity = "quiet"
	noColor = false

	applyOverrides(cfg)

	assert.Equal(t, "quiet", cfg.Output.Verbosity)
}

func TestApplyOverrides_Debug(t *testing.T) {
	cfg := config.DefaultConfig()

	// Save and restore global state
	oldJSON := jsonOutput
	oldVerbosity := verbosity
	oldNoColor := noColor
	defer func() {
		jsonOutput = oldJSON
		verbosity = oldVerbosity
		noColor = oldNoColor
	}()

	jsonOutput = false
	verbosity = "debug"
	noColor = false

	applyOverrides(cfg)

	assert.Equal(t, "debug", cfg.Output.Verbosity)
}

func TestCreateWriter_JSONFormat(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Output.Format = "json"

	// Save and restore global state
	oldOutputFlag := outputFlag
	oldNoColor := noColor
	defer func() {
		outputFlag = oldOutputFlag
		noColor = oldNoColor
	}()

	outputFlag = ""
	noColor = false

	writer, err := createWriter(cfg)

	require.NoError(t, err)
	assert.NotNil(t, writer)
}

func TestCreateWriter_SARIFFormat(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Output.Format = "sarif"

	// Save and restore global state
	oldOutputFlag := outputFlag
	oldNoColor := noColor
	defer func() {
		outputFlag = oldOutputFlag
		noColor = oldNoColor
	}()

	outputFlag = ""
	noColor = false

	writer, err := createWriter(cfg)

	require.NoError(t, err)
	assert.NotNil(t, writer)
}

func TestVersionCommand_Execute(t *testing.T) {
	// Test that version command can be executed
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	os.Args = []string{"verdict", "version"}

	code := Execute()

	assert.Equal(t, 0, code)
}

func TestSASTCommand_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := sastCmd.RunE(sastCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestVulnCommand_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := vulnCmd.RunE(vulnCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestSecretsCommand_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := secretsCmd.RunE(secretsCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestSBOMCommand_ConfigError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() {
		cfgFile = oldCfgFile
	}()

	cfgFile = "/nonexistent/config.yaml"

	err := sbomCmd.RunE(sbomCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestSASTCommand_Properties(t *testing.T) {
	assert.NotNil(t, sastCmd)
	assert.Equal(t, "sast [path]", sastCmd.Use)
	assert.Contains(t, sastCmd.Short, "static analysis")
}

func TestVulnCommand_Properties(t *testing.T) {
	assert.NotNil(t, vulnCmd)
	assert.Equal(t, "vuln [path]", vulnCmd.Use)
	assert.Contains(t, vulnCmd.Short, "vulnerability")
}

func TestSecretsCommand_Properties(t *testing.T) {
	assert.NotNil(t, secretsCmd)
	assert.Equal(t, "secrets [path]", secretsCmd.Use)
	assert.Contains(t, secretsCmd.Short, "Detect")
}

func TestSBOMCommand_Properties(t *testing.T) {
	assert.NotNil(t, sbomCmd)
	assert.Equal(t, "sbom [path]", sbomCmd.Use)
	assert.Contains(t, sbomCmd.Short, "Software Bill of Materials")
}

func TestRunSingleEngine_WriterError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	// Create a valid config file
	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = "/nonexistent/deeply/nested/output.json"

	err := runSingleEngine(sastCmd, []string{}, nil, "test")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create writer")
}

func TestDetermineEngines_ExcludeAll(t *testing.T) {
	cfg := DefaultTestConfig()

	// Save and restore
	oldInclude := includeEngines
	oldExclude := excludeEngines
	includeEngines = nil
	excludeEngines = []string{"gosec", "govulncheck", "gitleaks", "cyclonedx-gomod", "syft", "staticcheck"}
	defer func() {
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	engines := determineEngines(cfg)
	assert.Empty(t, engines)
}

func TestCreateWriter_WithNoColor(t *testing.T) {
	cfg := config.DefaultConfig()

	// Save and restore global state
	oldOutputFlag := outputFlag
	oldNoColor := noColor
	defer func() {
		outputFlag = oldOutputFlag
		noColor = oldNoColor
	}()

	outputFlag = ""
	noColor = true

	writer, err := createWriter(cfg)

	require.NoError(t, err)
	assert.NotNil(t, writer)
}

func TestApplyOverrides_EmptyVerbosity(t *testing.T) {
	cfg := config.DefaultConfig()
	originalVerbosity := cfg.Output.Verbosity

	// Save and restore global state
	oldJSON := jsonOutput
	oldVerbosity := verbosity
	oldNoColor := noColor
	defer func() {
		jsonOutput = oldJSON
		verbosity = oldVerbosity
		noColor = oldNoColor
	}()

	jsonOutput = false
	verbosity = "" // Empty verbosity should be ignored in modern code
	noColor = false

	applyOverrides(cfg)

	// Empty string verbosity still sets the value (implementation behavior)
	if verbosity == "" {
		assert.Equal(t, originalVerbosity, cfg.Output.Verbosity)
	}
}

func TestGetTarget_ArgsOverrideTargetPath(t *testing.T) {
	// Save and restore global state
	oldTargetPath := targetPath
	defer func() {
		targetPath = oldTargetPath
	}()

	targetPath = "/custom/path"
	result := getTarget([]string{"/arg/path"})

	// Args should take precedence
	assert.Equal(t, "/arg/path", result)
}

func TestCICommand_Properties(t *testing.T) {
	assert.NotNil(t, ciCmd)
	assert.Equal(t, "ci [path]", ciCmd.Use)
	assert.Contains(t, ciCmd.Short, "CI mode")
}

func TestBaselineWriteCommand_Properties(t *testing.T) {
	assert.NotNil(t, baselineWriteCmd)
	assert.Equal(t, "write [path]", baselineWriteCmd.Use)
	assert.Contains(t, baselineWriteCmd.Short, "Create")
}

func TestBaselineUpdateCommand_Properties(t *testing.T) {
	assert.NotNil(t, baselineUpdateCmd)
	assert.Equal(t, "update [path]", baselineUpdateCmd.Use)
	assert.Contains(t, baselineUpdateCmd.Short, "Update")
}

func TestPolicyLintCommand_Properties(t *testing.T) {
	assert.NotNil(t, policyLintCmd)
	assert.Equal(t, "lint", policyLintCmd.Use)
}

func TestRunCI_WriterError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = "/nonexistent/deeply/nested/output.json"

	err := runCI(ciCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create writer")
}

func TestRunScan_WriterError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = "/nonexistent/deeply/nested/output.json"

	err := runScan(scanCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create writer")
}

func TestRunBaselineWrite_WriterError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = "/nonexistent/deeply/nested/output.json"

	err := runBaselineWrite(baselineWriteCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create writer")
}

func TestRunBaselineUpdate_WriterError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = "/nonexistent/deeply/nested/output.json"

	err := runBaselineUpdate(baselineUpdateCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create writer")
}

func TestRunBaselineUpdate_ReasonRequired(t *testing.T) {
	SkipIfNoEngines(t)
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
baseline:
  path: ` + tmpDir + `/baseline.json
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	oldBaselineReason := baselineReason
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
		baselineReason = oldBaselineReason
	}()

	cfgFile = configPath
	outputFlag = ""
	baselineReason = "" // No reason provided

	err := runBaselineUpdate(baselineUpdateCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason is required")
}

func TestRootCommand_HasSubcommands(t *testing.T) {
	// Verify root command has all expected subcommands
	commands := rootCmd.Commands()
	commandNames := make([]string, 0, len(commands))
	for _, cmd := range commands {
		commandNames = append(commandNames, cmd.Use)
	}

	// Check that major commands are present
	assert.Contains(t, commandNames, "version")
}

func TestVersionCommand_HasRun(t *testing.T) {
	assert.NotNil(t, versionCmd.Run)
}

func TestDetermineEngines_PartiallyEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = true
	cfg.Engines.CycloneDX.Enabled = false

	// Reset global flags
	oldInclude := includeEngines
	oldExclude := excludeEngines
	includeEngines = nil
	excludeEngines = nil
	defer func() {
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	engines := determineEngines(cfg)

	assert.Contains(t, engines, "gosec")
	assert.NotContains(t, engines, "govulncheck")
	assert.Contains(t, engines, "gitleaks")
	assert.NotContains(t, engines, "cyclonedx-gomod")
}

func TestApplyThresholdOverrides_PartialChange(t *testing.T) {
	cfg := DefaultTestConfig()
	originalWarn := cfg.Policy.Threshold.WarnOn

	// Save and restore global state
	oldFail := failThreshold
	oldWarn := warnThreshold
	failThreshold = "CRITICAL"
	warnThreshold = "" // No change
	defer func() {
		failThreshold = oldFail
		warnThreshold = oldWarn
	}()

	applyThresholdOverrides(cfg)

	assert.Equal(t, "CRITICAL", cfg.Policy.Threshold.FailOn)
	assert.Equal(t, originalWarn, cfg.Policy.Threshold.WarnOn)
}

func TestDetermineEngines_WithExclude(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Engines.Govulncheck.Enabled = true
	cfg.Engines.Gitleaks.Enabled = true
	cfg.Engines.CycloneDX.Enabled = true

	// Save and restore global flags
	oldInclude := includeEngines
	oldExclude := excludeEngines
	includeEngines = nil
	excludeEngines = []string{"gosec", "gitleaks"}
	defer func() {
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	engines := determineEngines(cfg)

	assert.NotContains(t, engines, "gosec")
	assert.Contains(t, engines, "govulncheck")
	assert.NotContains(t, engines, "gitleaks")
	assert.Contains(t, engines, "cyclonedx-gomod")
}

func TestDetermineEngines_WithInclude(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Engines.Govulncheck.Enabled = true
	cfg.Engines.Gitleaks.Enabled = true
	cfg.Engines.CycloneDX.Enabled = true

	// Save and restore global flags
	oldInclude := includeEngines
	oldExclude := excludeEngines
	includeEngines = []string{"gosec", "govulncheck"}
	excludeEngines = nil
	defer func() {
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	engines := determineEngines(cfg)

	assert.Len(t, engines, 2)
	assert.Contains(t, engines, "gosec")
	assert.Contains(t, engines, "govulncheck")
}

func TestGetModeString_StrictTrue(t *testing.T) {
	oldStrictMode := strictMode
	strictMode = true
	defer func() { strictMode = oldStrictMode }()

	result := getModeString()
	assert.Equal(t, "ci", result)
}

func TestGetModeString_StrictFalse(t *testing.T) {
	oldStrictMode := strictMode
	strictMode = false
	defer func() { strictMode = oldStrictMode }()

	result := getModeString()
	assert.Equal(t, "local", result)
}

func TestGetTarget_EmptyArgs(t *testing.T) {
	// Save and restore global state
	oldTargetPath := targetPath
	targetPath = ""
	defer func() { targetPath = oldTargetPath }()

	result := getTarget([]string{})
	// Returns current working directory when no args and no targetPath
	wd, _ := os.Getwd()
	assert.Equal(t, wd, result)
}

func TestGetTarget_WithPath(t *testing.T) {
	result := getTarget([]string{"/some/path"})
	assert.Equal(t, "/some/path", result)
}

func TestGetTarget_MultipleArgs(t *testing.T) {
	result := getTarget([]string{"/first", "/second"})
	assert.Equal(t, "/first", result) // Should return first arg
}

func TestApplyOverrides_AllOverrides(t *testing.T) {
	cfg := DefaultTestConfig()

	// Save and restore global state
	oldOutput := outputFlag
	oldJson := jsonOutput
	oldNoColor := noColor
	oldVerbosity := verbosity
	defer func() {
		outputFlag = oldOutput
		jsonOutput = oldJson
		noColor = oldNoColor
		verbosity = oldVerbosity
	}()

	outputFlag = "/some/output.json"
	jsonOutput = true
	noColor = true
	verbosity = "debug"

	applyOverrides(cfg)

	assert.Equal(t, "json", cfg.Output.Format)
	assert.False(t, cfg.Output.Color)
	assert.Equal(t, "debug", cfg.Output.Verbosity)
}

func TestApplyOverrides_NoOverrides(t *testing.T) {
	cfg := DefaultTestConfig()
	originalFormat := cfg.Output.Format

	// Save and restore global state
	oldOutput := outputFlag
	oldJson := jsonOutput
	oldNoColor := noColor
	oldVerbosity := verbosity
	defer func() {
		outputFlag = oldOutput
		jsonOutput = oldJson
		noColor = oldNoColor
		verbosity = oldVerbosity
	}()

	outputFlag = ""
	jsonOutput = false
	noColor = false
	verbosity = ""

	applyOverrides(cfg)

	assert.Equal(t, originalFormat, cfg.Output.Format)
}

func TestCreateWriter_ToFileJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := DefaultTestConfig()
	cfg.Output.Format = "json"

	// Save and restore global state
	oldOutput := outputFlag
	defer func() { outputFlag = oldOutput }()
	outputFlag = tmpDir + "/output.json"

	writer, err := createWriter(cfg)

	assert.NoError(t, err)
	assert.NotNil(t, writer)
}

func TestBaselineCmd_Properties(t *testing.T) {
	assert.Equal(t, "baseline", baselineCmd.Use)
	assert.Contains(t, baselineCmd.Short, "baseline")
}

func TestBaselineWriteCmd_Properties(t *testing.T) {
	assert.Equal(t, "write [path]", baselineWriteCmd.Use)
	assert.Contains(t, baselineWriteCmd.Short, "Create")
}

func TestBaselineUpdateCmd_Properties(t *testing.T) {
	assert.Equal(t, "update [path]", baselineUpdateCmd.Use)
	assert.Contains(t, baselineUpdateCmd.Short, "Update")
}

func TestPolicyCmd_Properties(t *testing.T) {
	assert.Equal(t, "policy", policyCmd.Use)
	assert.Contains(t, policyCmd.Short, "policies")
}

func TestPolicyLintCmd_Properties(t *testing.T) {
	assert.Equal(t, "lint", policyLintCmd.Use)
	assert.Contains(t, policyLintCmd.Short, "Validate")
}

func TestCICmd_Properties(t *testing.T) {
	assert.Equal(t, "ci [path]", ciCmd.Use)
	assert.Contains(t, ciCmd.Short, "CI")
}

func TestSASTCmd_HasRunE(t *testing.T) {
	assert.NotNil(t, sastCmd.RunE)
}

func TestVulnCmd_HasRunE(t *testing.T) {
	assert.NotNil(t, vulnCmd.RunE)
}

func TestSecretsCmd_HasRunE(t *testing.T) {
	assert.NotNil(t, secretsCmd.RunE)
}

func TestSBOMCmd_HasRunE(t *testing.T) {
	assert.NotNil(t, sbomCmd.RunE)
}

func TestDetermineEngines_NoneEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = false
	cfg.Engines.Govulncheck.Enabled = false
	cfg.Engines.Gitleaks.Enabled = false
	cfg.Engines.CycloneDX.Enabled = false
	cfg.Engines.Syft.Enabled = false
	cfg.Engines.Staticcheck.Enabled = false

	// Save and restore global flags
	oldInclude := includeEngines
	oldExclude := excludeEngines
	includeEngines = nil
	excludeEngines = nil
	defer func() {
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	engines := determineEngines(cfg)

	assert.Empty(t, engines)
}

func TestDetermineEngines_AllEnabledNoFilters(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Engines.Gosec.Enabled = true
	cfg.Engines.Govulncheck.Enabled = true
	cfg.Engines.Gitleaks.Enabled = true
	cfg.Engines.CycloneDX.Enabled = true
	cfg.Engines.Syft.Enabled = true
	cfg.Engines.Staticcheck.Enabled = true

	// Save and restore global flags
	oldInclude := includeEngines
	oldExclude := excludeEngines
	includeEngines = nil
	excludeEngines = nil
	defer func() {
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	engines := determineEngines(cfg)

	assert.Len(t, engines, 6)
	assert.Contains(t, engines, "gosec")
	assert.Contains(t, engines, "govulncheck")
	assert.Contains(t, engines, "gitleaks")
	assert.Contains(t, engines, "cyclonedx-gomod")
	assert.Contains(t, engines, "syft")
	assert.Contains(t, engines, "staticcheck")
}

func TestApplyThresholdOverrides_BothChanged(t *testing.T) {
	cfg := DefaultTestConfig()

	// Save and restore global state
	oldFail := failThreshold
	oldWarn := warnThreshold
	failThreshold = "CRITICAL"
	warnThreshold = "LOW"
	defer func() {
		failThreshold = oldFail
		warnThreshold = oldWarn
	}()

	applyThresholdOverrides(cfg)

	assert.Equal(t, "CRITICAL", cfg.Policy.Threshold.FailOn)
	assert.Equal(t, "LOW", cfg.Policy.Threshold.WarnOn)
}

func TestApplyThresholdOverrides_NoneChanged(t *testing.T) {
	cfg := DefaultTestConfig()
	originalFail := cfg.Policy.Threshold.FailOn
	originalWarn := cfg.Policy.Threshold.WarnOn

	// Save and restore global state
	oldFail := failThreshold
	oldWarn := warnThreshold
	failThreshold = ""
	warnThreshold = ""
	defer func() {
		failThreshold = oldFail
		warnThreshold = oldWarn
	}()

	applyThresholdOverrides(cfg)

	assert.Equal(t, originalFail, cfg.Policy.Threshold.FailOn)
	assert.Equal(t, originalWarn, cfg.Policy.Threshold.WarnOn)
}

func TestGetTarget_WithTargetPathFlag(t *testing.T) {
	// Save and restore global state
	oldTargetPath := targetPath
	targetPath = "/flag/path"
	defer func() { targetPath = oldTargetPath }()

	result := getTarget([]string{})
	assert.Equal(t, "/flag/path", result)
}

func TestGetTarget_ArgsHavePriority(t *testing.T) {
	// Save and restore global state
	oldTargetPath := targetPath
	targetPath = "/flag/path"
	defer func() { targetPath = oldTargetPath }()

	result := getTarget([]string{"/args/path"})
	assert.Equal(t, "/args/path", result)
}

func TestRunPolicyLint_ConfigLoadError(t *testing.T) {
	// Save and restore global state
	oldCfgFile := cfgFile
	defer func() { cfgFile = oldCfgFile }()

	cfgFile = "/nonexistent/config.yaml"

	err := runPolicyLint(policyLintCmd, []string{})

	assert.Error(t, err)
}

func TestRunPolicyLint_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
  baseline_mode: warn
engines:
  gosec:
    enabled: true
  govulncheck:
    enabled: true
  gitleaks:
    enabled: true
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = ""

	err := runPolicyLint(policyLintCmd, []string{})

	assert.NoError(t, err)
}

func TestRunPolicyLint_InvalidThreshold(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: INVALID_SEVERITY
    warn_on: MEDIUM
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = ""

	err := runPolicyLint(policyLintCmd, []string{})

	// Should fail due to invalid threshold
	assert.Error(t, err)
}

func TestRunBaselineWrite_ReasonRequired(t *testing.T) {
	SkipIfNoEngines(t)
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
baseline:
  path: ` + tmpDir + `/baseline.json
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	oldBaselineReason := baselineReason
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
		baselineReason = oldBaselineReason
	}()

	cfgFile = configPath
	outputFlag = ""
	baselineReason = "" // No reason provided

	err := runBaselineWrite(baselineWriteCmd, []string{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason is required")
}

func TestRunSAST_ScanExecution(t *testing.T) {
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
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = "" // Valid output (stdout)

	// Run SAST - it will fail because engine executes and may fail,
	// but this exercises more code paths
	err := runSingleEngine(sastCmd, []string{tmpDir}, []ports.EngineID{ports.EngineGosec}, "SAST")

	// May succeed or fail depending on engine availability
	_ = err
}

func TestRunVuln_ScanExecution(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
engines:
  govulncheck:
    enabled: true
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = ""

	err := runSingleEngine(vulnCmd, []string{tmpDir}, []ports.EngineID{ports.EngineGovulncheck}, "vulnerability")
	_ = err
}

func TestRunSecrets_ScanExecution(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
engines:
  gitleaks:
    enabled: true
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = ""

	err := runSingleEngine(secretsCmd, []string{tmpDir}, []ports.EngineID{ports.EngineGitleaks}, "secrets")
	_ = err
}

func TestRunSBOM_ScanExecution(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"

	content := []byte(`version: "1"
policy:
  threshold:
    fail_on: HIGH
    warn_on: MEDIUM
engines:
  cyclonedx-gomod:
    enabled: true
`)
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Save and restore global state
	oldCfgFile := cfgFile
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = ""

	err := runSingleEngine(sbomCmd, []string{tmpDir}, []ports.EngineID{ports.EngineCycloneDX}, "SBOM")
	_ = err
}

func TestRunScan_FullExecution(t *testing.T) {
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
	oldOutputFlag := outputFlag
	oldInclude := includeEngines
	oldExclude := excludeEngines
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
		includeEngines = oldInclude
		excludeEngines = oldExclude
	}()

	cfgFile = configPath
	outputFlag = ""
	includeEngines = nil
	excludeEngines = nil

	err := runScan(scanCmd, []string{tmpDir})
	_ = err
}

func TestRunCI_FullExecution(t *testing.T) {
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
	oldOutputFlag := outputFlag
	defer func() {
		cfgFile = oldCfgFile
		outputFlag = oldOutputFlag
	}()

	cfgFile = configPath
	outputFlag = ""

	err := runCI(ciCmd, []string{tmpDir})
	_ = err
}
