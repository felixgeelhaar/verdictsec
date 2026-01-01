package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/spf13/cobra"
)

var (
	baselineOutput string
	baselineReason string
	pruneAfterDays int
)

// baselineCmd is the parent command for baseline operations
var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage security baselines",
	Long: `Manage security baselines for tracking known findings.

Baselines record fingerprints of existing findings so they can be
excluded from future scans. This is useful for:
  - Ignoring known false positives
  - Tracking legacy issues separately from new findings
  - Gradual remediation of technical debt

Examples:
  verdict baseline write           # Create new baseline from current scan
  verdict baseline update          # Update existing baseline with new findings`,
}

// baselineWriteCmd creates a new baseline
var baselineWriteCmd = &cobra.Command{
	Use:   "write [path]",
	Short: "Create a new baseline from current scan",
	Long: `Run a security scan and create a baseline from all findings.

This will overwrite any existing baseline file.
A reason is required to document why findings are being baselined.

Examples:
  verdict baseline write --reason "Legacy code, addressing in Q2"
  verdict baseline write ./myproject --reason "Initial baseline"
  verdict baseline write -o .verdict/baseline.json --reason "False positives"`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBaselineWrite,
}

// baselineUpdateCmd updates an existing baseline
var baselineUpdateCmd = &cobra.Command{
	Use:   "update [path]",
	Short: "Update existing baseline with new findings",
	Long: `Run a security scan and merge new findings into the existing baseline.

New findings are added, and existing entries are updated with fresh timestamps.
A reason is required to document why new findings are being baselined.
Optionally prune entries that haven't been seen for a specified number of days.

Examples:
  verdict baseline update --reason "Sprint cleanup"
  verdict baseline update --reason "Addressing in Q3" --prune 90`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBaselineUpdate,
}

func init() {
	// Baseline write flags
	baselineWriteCmd.Flags().StringVarP(&baselineOutput, "output", "o", "", "output file path (default: .verdict/baseline.json)")
	baselineWriteCmd.Flags().StringVarP(&baselineReason, "reason", "r", "", "reason for baselining (required)")
	_ = baselineWriteCmd.MarkFlagRequired("reason")

	// Baseline update flags
	baselineUpdateCmd.Flags().IntVar(&pruneAfterDays, "prune", 0, "remove entries not seen in N days (0 = don't prune)")
	baselineUpdateCmd.Flags().StringVarP(&baselineReason, "reason", "r", "", "reason for baselining new findings (required)")
	_ = baselineUpdateCmd.MarkFlagRequired("reason")

	// Add subcommands
	baselineCmd.AddCommand(baselineWriteCmd)
	baselineCmd.AddCommand(baselineUpdateCmd)

	rootCmd.AddCommand(baselineCmd)
}

func runBaselineWrite(cmd *cobra.Command, args []string) error {
	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Create writer
	writer, err := createWriter(cfg)
	if err != nil {
		return fmt.Errorf("failed to create writer: %w", err)
	}

	// Get target path
	target := getTarget(args)

	_ = writer.WriteProgress(fmt.Sprintf("Scanning %s to create baseline...", target))

	// Create engine registry and normalizer
	registry := engines.NewDefaultRegistry()
	normalizer := engines.NewCompositeNormalizer()

	// Create run scan use case
	scanUseCase := usecases.NewRunScanUseCase(registry, normalizer, writer)

	// Get all enabled engines
	var engineIDs []ports.EngineID
	if cfg.Engines.Gosec.Enabled {
		engineIDs = append(engineIDs, ports.EngineGosec)
	}
	if cfg.Engines.Govulncheck.Enabled {
		engineIDs = append(engineIDs, ports.EngineGovulncheck)
	}
	if cfg.Engines.Gitleaks.Enabled {
		engineIDs = append(engineIDs, ports.EngineGitleaks)
	}

	// Execute scan
	scanInput := usecases.RunScanInput{
		Target:     ports.NewTarget(target),
		Config:     cfg.ToPortsConfig(),
		Mode:       "local",
		Engines:    engineIDs,
		Parallel:   true,
		MaxWorkers: 4,
	}

	scanOutput, err := scanUseCase.Execute(ctx, scanInput)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Determine baseline path
	blPath := baselineOutput
	if blPath == "" {
		blPath = cfg.Baseline.Path
		if blPath == "" {
			blPath = ".verdict/baseline.json"
		}
	}

	// Create baseline store
	store := baseline.NewStoreWithPath(blPath)

	// Create baseline use case
	baselineUseCase := usecases.NewWriteBaselineUseCase(store, writer)

	// Write baseline
	writeInput := usecases.WriteBaselineInput{
		Assessment: scanOutput.Assessment,
		Target:     target,
		Path:       blPath,
		Reason:     baselineReason,
	}

	output, err := baselineUseCase.Write(writeInput)
	if err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}

	fmt.Printf("Baseline created: %s (%d entries)\n", output.Path, output.EntriesAdded)
	return nil
}

func runBaselineUpdate(cmd *cobra.Command, args []string) error {
	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Create writer
	writer, err := createWriter(cfg)
	if err != nil {
		return fmt.Errorf("failed to create writer: %w", err)
	}

	// Get target path
	target := getTarget(args)

	// Determine baseline path
	blPath := cfg.Baseline.Path
	if blPath == "" {
		blPath = ".verdict/baseline.json"
	}

	// Load existing baseline
	store := baseline.NewStoreWithPath(blPath)
	bl, err := store.Load()
	if err != nil {
		return fmt.Errorf("failed to load existing baseline: %w", err)
	}

	_ = writer.WriteProgress(fmt.Sprintf("Updating baseline %s from scan of %s...", blPath, target))

	// Create engine registry and normalizer
	registry := engines.NewDefaultRegistry()
	normalizer := engines.NewCompositeNormalizer()

	// Create run scan use case
	scanUseCase := usecases.NewRunScanUseCase(registry, normalizer, writer)

	// Get all enabled engines
	var engineIDs []ports.EngineID
	if cfg.Engines.Gosec.Enabled {
		engineIDs = append(engineIDs, ports.EngineGosec)
	}
	if cfg.Engines.Govulncheck.Enabled {
		engineIDs = append(engineIDs, ports.EngineGovulncheck)
	}
	if cfg.Engines.Gitleaks.Enabled {
		engineIDs = append(engineIDs, ports.EngineGitleaks)
	}

	// Execute scan
	scanInput := usecases.RunScanInput{
		Target:     ports.NewTarget(target),
		Config:     cfg.ToPortsConfig(),
		Mode:       "local",
		Engines:    engineIDs,
		Parallel:   true,
		MaxWorkers: 4,
	}

	scanOutput, err := scanUseCase.Execute(ctx, scanInput)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Create baseline use case
	baselineUseCase := usecases.NewWriteBaselineUseCase(store, writer)

	// Update baseline
	updateInput := usecases.UpdateBaselineInput{
		Assessment:     scanOutput.Assessment,
		Baseline:       bl,
		PruneAfterDays: pruneAfterDays,
		Reason:         baselineReason,
	}

	output, err := baselineUseCase.Update(updateInput)
	if err != nil {
		return fmt.Errorf("failed to update baseline: %w", err)
	}

	fmt.Printf("Baseline updated: +%d new, ~%d updated", output.EntriesAdded, output.EntriesUpdated)
	if output.EntriesPruned > 0 {
		fmt.Printf(", -%d pruned", output.EntriesPruned)
	}
	fmt.Printf(" (total: %d)\n", output.Baseline.Count())

	return nil
}
