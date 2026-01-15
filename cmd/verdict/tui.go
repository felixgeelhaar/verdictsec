package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	domainBaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/tui"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/writers"
	"github.com/spf13/cobra"
)

// tuiCmd launches an interactive TUI for exploring security findings
var tuiCmd = &cobra.Command{
	Use:   "tui [path]",
	Short: "Interactive TUI for exploring security findings",
	Long: `Launch an interactive terminal interface to explore scan results.

The TUI provides:
  - Navigable list of all findings with keyboard navigation
  - Detailed view of each finding with full information
  - Filter by severity (1-4), engine, type, and status (n/e/s)
  - Search across findings (/)
  - Add findings to baseline inline (b)
  - Help overlay (?)

Key bindings:
  j/k, ↑/↓     Navigate list
  Enter/Tab    Toggle detail view focus
  1-4          Toggle severity filter (CRIT, HIGH, MED, LOW)
  n/e/s        Filter by status (new/existing/suppressed)
  c            Clear all filters
  /            Enter search mode
  b            Add selected finding to baseline
  ?            Toggle help
  q, Ctrl+C    Quit

Examples:
  verdict tui                    # Scan and launch TUI
  verdict tui ./myproject        # Scan specific path
  verdict tui --baseline .verdict/baseline.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTUI,
}

func init() {
	// TUI-specific flags - reuse scan flags where applicable
	tuiCmd.Flags().StringVar(&baselinePath, "baseline", "", "baseline file path")
	tuiCmd.Flags().StringSliceVar(&excludeEngines, "exclude", nil, "engines to exclude")
	tuiCmd.Flags().StringSliceVar(&includeEngines, "include", nil, "engines to include (only these will run)")
	tuiCmd.Flags().BoolVar(&noInline, "no-inline", false, "disable inline suppression comments (// verdict:ignore)")

	rootCmd.AddCommand(tuiCmd)
}

func runTUI(cmd *cobra.Command, args []string) error {
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

	// Get target path
	target := getTarget(args)

	// Create a simple progress writer for scan phase
	progressWriter := writers.NewConsoleWriter(
		writers.WithErrorOutput(os.Stderr),
		writers.WithColor(!noColor),
	)
	_ = progressWriter.WriteProgress(fmt.Sprintf("Scanning %s...", target))

	// Create engine registry
	registry := engines.NewDefaultRegistry()

	// Warn about missing engines
	portsCfg := cfg.ToPortsConfig()
	WarnMissingEngines(registry, portsCfg)

	// Create composite normalizer
	normalizer := engines.NewCompositeNormalizer()

	// Create run scan use case
	scanUseCase := usecases.NewRunScanUseCase(registry, normalizer, progressWriter)

	// Determine which engines to run
	engineIDs := determineEngines(cfg)
	_ = progressWriter.WriteProgress(fmt.Sprintf("Running engines: %v", engineIDs))

	// Convert to ports.EngineID
	var portsEngineIDs []ports.EngineID
	for _, id := range engineIDs {
		portsEngineIDs = append(portsEngineIDs, ports.EngineID(id))
	}

	// Execute scan
	scanInput := usecases.RunScanInput{
		Target:     ports.NewTarget(target),
		Config:     cfg.ToPortsConfig(),
		Mode:       getModeString(),
		Engines:    portsEngineIDs,
		Parallel:   true,
		MaxWorkers: 4,
	}

	scanOutput, err := scanUseCase.Execute(ctx, scanInput)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Load baseline if specified
	var bl *domainBaseline.Baseline
	blPath := baselinePath
	if blPath == "" {
		blPath = cfg.Baseline.Path
	}

	if blPath != "" {
		store := baseline.NewStoreWithPath(blPath)
		bl, err = store.Load()
		if err != nil {
			_ = progressWriter.WriteProgress(fmt.Sprintf("Warning: failed to load baseline: %v", err))
			bl = domainBaseline.NewBaseline("")
		} else {
			_ = progressWriter.WriteProgress(fmt.Sprintf("Loaded baseline with %d fingerprints", bl.Count()))
		}
	} else {
		bl = domainBaseline.NewBaseline("")
		// Set default baseline path for saving
		blPath = ".verdict/baseline.json"
	}

	// Create evaluate policy use case
	evalUseCase := usecases.NewEvaluatePolicyUseCase(nil)

	// Build policy
	pol := cfg.ToDomainPolicy()

	// Determine mode
	mode := policy.ModeLocal
	if strictMode {
		mode = policy.ModeCI
	}

	// Determine if inline suppressions are enabled
	inlineSuppressionsEnabled := cfg.IsInlineSuppressionsEnabled() && !noInline

	// Evaluate against policy
	evalInput := usecases.EvaluatePolicyInput{
		Assessment:                scanOutput.Assessment,
		Policy:                    &pol,
		Baseline:                  bl,
		Mode:                      mode,
		InlineSuppressionsEnabled: inlineSuppressionsEnabled,
		TargetDir:                 target,
	}
	evalOutput := evalUseCase.Execute(ctx, evalInput)

	// Check if we have findings to display
	if len(scanOutput.Assessment.Findings()) == 0 {
		_ = progressWriter.WriteProgress("No findings to display. Scan completed successfully!")
		return nil
	}

	_ = progressWriter.WriteProgress(fmt.Sprintf("Found %d findings. Launching TUI...", len(scanOutput.Assessment.Findings())))

	// Create TUI model
	model := tui.New(
		scanOutput.Assessment,
		evalOutput.Result,
		bl,
		blPath,
		!noColor,
	)

	// Run bubbletea program with alternate screen
	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	return nil
}
