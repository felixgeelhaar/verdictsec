package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/writers"
	"github.com/felixgeelhaar/verdictsec/pkg/exitcode"
	"github.com/spf13/cobra"
)

// Version information set at build time
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

// Global flags
var (
	cfgFile     string
	outputFlag  string
	verbosity   string
	noColor     bool
	jsonOutput  bool
	sarifOutput bool
	strictMode  bool
	targetPath  string
)

// rootCmd is the base command for verdict
var rootCmd = &cobra.Command{
	Use:   "verdict",
	Short: "VerdictSec - Security assessment for Go projects",
	Long: `VerdictSec is a comprehensive security assessment tool for Go projects.

It orchestrates multiple security engines (gosec, govulncheck, gitleaks, etc.)
to provide unified security analysis with configurable policies and baselines.

Examples:
  verdict scan                    # Full security scan
  verdict ci                      # CI mode (strict, fails on warnings)
  verdict sast                    # Static analysis only
  verdict vuln                    # Vulnerability scan only
  verdict baseline write          # Create a baseline from current findings`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Configure colors
		if noColor {
			color.NoColor = true
		}
		return nil
	},
}

// versionCmd shows version information
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("VerdictSec %s\n", version)
		fmt.Printf("  Commit:  %s\n", commit)
		fmt.Printf("  Built:   %s\n", buildDate)
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: .verdict/config.yaml)")
	rootCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "", "output file (default: stdout)")
	rootCmd.PersistentFlags().StringVarP(&verbosity, "verbosity", "v", "normal", "verbosity level (quiet, normal, verbose, debug)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&sarifOutput, "sarif", false, "output in SARIF format")
	rootCmd.PersistentFlags().BoolVar(&strictMode, "strict", false, "strict mode (fail on warnings)")

	// Add version command
	rootCmd.AddCommand(versionCmd)
}

// Execute runs the root command
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitcode.Error
	}
	return exitcode.Success
}

// loadConfig loads the configuration from file and CLI overrides
func loadConfig() (*config.Config, error) {
	loader := config.NewLoader()

	var cfg *config.Config
	var err error

	if cfgFile != "" {
		cfg, err = loader.LoadFromFile(cfgFile)
	} else {
		cfg, err = loader.Load()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Apply CLI overrides
	applyOverrides(cfg)

	return cfg, nil
}

// applyOverrides applies CLI flag overrides to the config
func applyOverrides(cfg *config.Config) {
	// Output format (sarif takes precedence over json)
	if sarifOutput {
		cfg.Output.Format = "sarif"
	} else if jsonOutput {
		cfg.Output.Format = "json"
	}

	// Verbosity
	if verbosity != "" {
		cfg.Output.Verbosity = verbosity
	}

	// Color
	if noColor {
		cfg.Output.Color = false
	}
}

// createWriter creates the appropriate writer based on config
func createWriter(cfg *config.Config) (ports.ArtifactWriter, error) {
	factory := writers.NewFactory()

	outputConfig := ports.OutputConfig{
		Color:     cfg.Output.Color && !noColor,
		Verbosity: cfg.GetVerbosity(),
	}

	format := cfg.GetOutputFormat()

	if outputFlag != "" {
		return factory.CreateToFile(format, outputFlag, outputConfig)
	}

	return factory.Create(format, outputConfig)
}

// getTarget returns the target path from args or current directory
func getTarget(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	if targetPath != "" {
		return targetPath
	}
	// Default to current directory
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}
