package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/spf13/cobra"
)

var (
	initForce bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize VerdictSec configuration",
	Long: `Initialize VerdictSec configuration for your project.

This command creates a .verdict directory with:
  - config.yaml: Default configuration with sensible defaults
  - baseline.json: Empty baseline for suppressing known findings

It also detects available security engines and reports their status.

Examples:
  verdict init              # Initialize in current directory
  verdict init --force      # Overwrite existing configuration`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().BoolVarP(&initForce, "force", "f", false, "overwrite existing configuration")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()

	if noColor {
		green = fmt.Sprint
		yellow = fmt.Sprint
		red = fmt.Sprint
		cyan = fmt.Sprint
		bold = fmt.Sprint
	}

	configDir := config.DefaultConfigDir
	configPath := filepath.Join(configDir, config.DefaultConfigFile)
	baselinePath := filepath.Join(configDir, "baseline.json")

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		if !initForce {
			return fmt.Errorf("configuration already exists at %s\nUse --force to overwrite", configPath)
		}
		fmt.Printf("%s Overwriting existing configuration\n", yellow("!"))
	}

	// Create .verdict directory
	if err := os.MkdirAll(configDir, 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate default config
	if err := config.GenerateDefaultConfig(configPath); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	fmt.Printf("%s Created %s\n", green("\u2713"), configPath)

	// Create empty baseline if it doesn't exist
	if _, err := os.Stat(baselinePath); os.IsNotExist(err) {
		emptyBaseline := `{
  "version": "1",
  "scope": "",
  "entries": []
}
`
		if err := os.WriteFile(baselinePath, []byte(emptyBaseline), 0600); err != nil {
			return fmt.Errorf("failed to create baseline file: %w", err)
		}
		fmt.Printf("%s Created %s\n", green("\u2713"), baselinePath)
	} else {
		fmt.Printf("%s Baseline already exists at %s\n", yellow("!"), baselinePath)
	}

	// Detect available engines
	fmt.Printf("\n%s\n", bold("Engine Status:"))
	registry := engines.NewDefaultRegistry()
	allEngines := registry.All()

	availableCount := 0
	for _, engine := range allEngines {
		info := engine.Info()
		if engine.IsAvailable() {
			version := engine.Version()
			fmt.Printf("  %s %-12s %s (%s)\n", green("\u2713"), info.Name, cyan(version), info.Capability)
			availableCount++
		} else {
			fmt.Printf("  %s %-12s %s\n", red("\u2717"), info.Name, yellow("not installed"))
			fmt.Printf("      Install: %s\n", info.InstallCmd)
		}
	}

	fmt.Printf("\n%s %d/%d engines available\n", bold("Summary:"), availableCount, len(allEngines))

	// Show next steps
	fmt.Printf("\n%s\n", bold("Next Steps:"))
	fmt.Println("  1. Review and customize .verdict/config.yaml")
	fmt.Println("  2. Install any missing engines shown above")
	fmt.Println("  3. Run 'verdict scan' to perform a security scan")
	fmt.Println("  4. Run 'verdict baseline write' to create a baseline from current findings")

	return nil
}
