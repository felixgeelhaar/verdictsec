package main

import (
	"time"

	"github.com/spf13/cobra"
)

var (
	watchDebounceStandalone time.Duration
	watchEngines            []string
)

var watchCmd = &cobra.Command{
	Use:   "watch [path]",
	Short: "Watch for file changes and continuously scan",
	Long: `Monitor files and re-run security scan on changes.

This command is equivalent to 'verdict scan --watch' but provides
a more discoverable way to use watch mode.

Watch mode:
  - Monitors Go files (.go, .mod, .sum) for changes
  - Debounces rapid changes to avoid excessive rescans
  - Clears terminal and shows fresh scan results
  - Exits cleanly on Ctrl+C

Examples:
  verdict watch                    # Watch current directory
  verdict watch ./src              # Watch specific path
  verdict watch --debounce=1s      # Custom debounce duration
  verdict watch --engines=gosec    # Only run specific engines`,
	Args: cobra.MaximumNArgs(1),
	RunE: runWatchCmd,
}

func init() {
	watchCmd.Flags().DurationVar(&watchDebounceStandalone, "debounce", 500*time.Millisecond, "debounce duration for file changes")
	watchCmd.Flags().StringSliceVar(&watchEngines, "engines", nil, "specific engines to run (default: all)")
	rootCmd.AddCommand(watchCmd)
}

func runWatchCmd(cmd *cobra.Command, args []string) error {
	// Enable watch mode and delegate to scan command
	watchMode = true
	watchDebounce = watchDebounceStandalone

	if len(watchEngines) > 0 {
		includeEngines = watchEngines
	}

	return runScan(cmd, args)
}
