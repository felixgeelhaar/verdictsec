package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/spf13/cobra"
)

var (
	enginesJSONOutput bool
	enginesCheck      bool
)

// enginesCmd shows status of all security engines
var enginesCmd = &cobra.Command{
	Use:   "engines",
	Short: "Show status of security engines",
	Long: `Display the status of all security scanning engines.

Shows which engines are installed, their versions, and installation
instructions for missing engines.

Examples:
  verdict engines               # Show engine status table
  verdict engines --json        # Output as JSON
  verdict engines --check       # Exit with code 1 if engines missing`,
	RunE: runEngines,
}

func init() {
	enginesCmd.Flags().BoolVar(&enginesJSONOutput, "json", false, "output in JSON format")
	enginesCmd.Flags().BoolVar(&enginesCheck, "check", false, "exit with code 1 if any enabled engines are missing")
	rootCmd.AddCommand(enginesCmd)
}

func runEngines(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Create registry with all engines
	registry := engines.NewDefaultRegistry()

	// Get status for all engines
	portsCfg := cfg.ToPortsConfig()
	statuses := registry.Status(portsCfg)

	// Sort by engine ID for consistent output
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Info.ID < statuses[j].Info.ID
	})

	if enginesJSONOutput {
		return outputEnginesJSON(statuses)
	}

	return outputEnginesTable(statuses, enginesCheck)
}

// engineStatusJSON represents engine status for JSON output
type engineStatusJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Capability  string `json:"capability"`
	Available   bool   `json:"available"`
	Version     string `json:"version,omitempty"`
	Enabled     bool   `json:"enabled"`
	InstallCmd  string `json:"install_cmd"`
	Homepage    string `json:"homepage"`
}

func outputEnginesJSON(statuses []engines.EngineStatus) error {
	output := make([]engineStatusJSON, 0, len(statuses))

	for _, s := range statuses {
		output = append(output, engineStatusJSON{
			ID:          string(s.Info.ID),
			Name:        s.Info.Name,
			Description: s.Info.Description,
			Capability:  string(s.Info.Capability),
			Available:   s.Available,
			Version:     s.Version,
			Enabled:     s.Enabled,
			InstallCmd:  s.Info.InstallCmd,
			Homepage:    s.Info.Homepage,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputEnginesTable(statuses []engines.EngineStatus, checkMode bool) error {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	fmt.Println()
	fmt.Println(bold("Security Engines Status"))
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("  %-18s %-12s %-12s %s\n", "Engine", "Status", "Version", "Capability")
	fmt.Println(strings.Repeat("─", 70))

	var missingEngines []engines.EngineStatus

	for _, s := range statuses {
		var statusStr, versionStr string
		var icon string

		if s.Available {
			icon = green("✓")
			statusStr = green("installed")
			versionStr = s.Version
			if versionStr == "" || versionStr == "unknown" {
				versionStr = dim("unknown")
			}
		} else {
			icon = red("✗")
			statusStr = red("missing")
			versionStr = dim("-")
			if s.Enabled {
				missingEngines = append(missingEngines, s)
			}
		}

		// Show disabled engines differently
		if !s.Enabled {
			statusStr = yellow("disabled")
		}

		fmt.Printf("%s %-18s %-12s %-12s %s\n",
			icon,
			s.Info.Name,
			statusStr,
			versionStr,
			capabilityLabel(s.Info.Capability),
		)
	}

	fmt.Println(strings.Repeat("─", 70))
	fmt.Println()

	// Show installation commands for missing engines
	if len(missingEngines) > 0 {
		fmt.Println(bold("Missing Engines"))
		fmt.Println("To install missing engines, run:")
		fmt.Println()

		for _, s := range missingEngines {
			fmt.Printf("  %s\n", dim(s.Info.InstallCmd))
		}
		fmt.Println()

		// In check mode, exit with error if engines are missing
		if checkMode {
			fmt.Fprintf(os.Stderr, "%s %d required engine(s) not installed\n",
				red("Error:"), len(missingEngines))
			os.Exit(1)
		}
	} else {
		fmt.Println(green("All enabled engines are installed."))
		fmt.Println()
	}

	return nil
}

func capabilityLabel(cap ports.Capability) string {
	switch cap {
	case ports.CapabilitySAST:
		return "Static Analysis"
	case ports.CapabilityVuln:
		return "Vulnerability"
	case ports.CapabilitySecrets:
		return "Secrets"
	case ports.CapabilitySBOM:
		return "SBOM"
	default:
		return string(cap)
	}
}

// WarnMissingEngines prints a warning for missing enabled engines.
// Returns true if any warnings were printed.
func WarnMissingEngines(registry *engines.Registry, cfg ports.Config) bool {
	yellow := color.New(color.FgYellow).SprintFunc()

	unavailable := registry.Unavailable()
	var warned bool

	for _, engine := range unavailable {
		// Check if engine is enabled in config
		if engineCfg, ok := cfg.Engines[engine.ID()]; ok && !engineCfg.Enabled {
			continue // Skip disabled engines
		}

		info := engine.Info()
		fmt.Fprintf(os.Stderr, "%s Engine %s is enabled but not installed\n",
			yellow("⚠ Warning:"), info.Name)
		fmt.Fprintf(os.Stderr, "  Install with: %s\n\n", info.InstallCmd)
		warned = true
	}

	return warned
}
