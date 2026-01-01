package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	domainBaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/watcher"
	"github.com/felixgeelhaar/verdictsec/pkg/exitcode"
	"github.com/spf13/cobra"
)

var (
	baselinePath   string
	policyPath     string
	failThreshold  string
	warnThreshold  string
	excludeEngines []string
	includeEngines []string
	summaryOnly    bool
	watchMode      bool
	watchDebounce  time.Duration
)

// scanCmd performs a full security scan
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run a full security scan",
	Long: `Run a comprehensive security scan using all enabled engines.

This command orchestrates multiple security tools:
  - gosec: Static analysis for Go security issues
  - govulncheck: Vulnerability scanning for dependencies
  - gitleaks: Secret detection
  - cyclonedx-gomod: SBOM generation

Examples:
  verdict scan                     # Scan current directory
  verdict scan ./myproject         # Scan specific path
  verdict scan --json              # Output as JSON
  verdict scan --strict            # Fail on warnings
  verdict scan --baseline .verdict/baseline.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	// Scan-specific flags
	scanCmd.Flags().StringVar(&baselinePath, "baseline", "", "baseline file path")
	scanCmd.Flags().StringVar(&policyPath, "policy", "", "policy file path (overrides config)")
	scanCmd.Flags().StringVar(&failThreshold, "fail-on", "", "severity threshold to fail (critical, high, medium, low)")
	scanCmd.Flags().StringVar(&warnThreshold, "warn-on", "", "severity threshold to warn (critical, high, medium, low)")
	scanCmd.Flags().StringSliceVar(&excludeEngines, "exclude", nil, "engines to exclude")
	scanCmd.Flags().StringSliceVar(&includeEngines, "include", nil, "engines to include (only these will run)")
	scanCmd.Flags().BoolVar(&summaryOnly, "summary", false, "show summary only")
	scanCmd.Flags().BoolVarP(&watchMode, "watch", "w", false, "watch for file changes and re-run scan")
	scanCmd.Flags().DurationVar(&watchDebounce, "watch-debounce", 500*time.Millisecond, "debounce duration for watch mode")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
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

	// Apply command-specific overrides
	applyThresholdOverrides(cfg)

	// Create writer
	writer, err := createWriter(cfg)
	if err != nil {
		return fmt.Errorf("failed to create writer: %w", err)
	}

	// Get target path
	target := getTarget(args)

	// If watch mode is enabled, run the watcher
	if watchMode {
		return runWatchMode(ctx, cfg, target, writer)
	}

	// Write progress
	_ = writer.WriteProgress(fmt.Sprintf("Starting security scan of %s", target))

	// Create engine registry
	registry := engines.NewDefaultRegistry()

	// Create composite normalizer
	normalizer := engines.NewCompositeNormalizer()

	// Create run scan use case
	scanUseCase := usecases.NewRunScanUseCase(registry, normalizer, writer)

	// Determine which engines to run
	engineIDs := determineEngines(cfg)
	_ = writer.WriteProgress(fmt.Sprintf("Running engines: %v", engineIDs))

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
	if baselinePath != "" || cfg.Baseline.Path != "" {
		blPath := baselinePath
		if blPath == "" {
			blPath = cfg.Baseline.Path
		}

		store := baseline.NewStoreWithPath(blPath)
		bl, err = store.Load()
		if err != nil {
			_ = writer.WriteProgress(fmt.Sprintf("Warning: failed to load baseline: %v", err))
			bl = domainBaseline.NewBaseline("")
		} else {
			_ = writer.WriteProgress(fmt.Sprintf("Loaded baseline with %d fingerprints", bl.Count()))
		}
	} else {
		bl = domainBaseline.NewBaseline("")
	}

	// Create evaluate policy use case
	evalUseCase := usecases.NewEvaluatePolicyUseCase(nil) // nil writer - we'll handle output ourselves

	// Build policy
	pol := cfg.ToDomainPolicy()

	// Determine mode
	mode := policy.ModeLocal
	if strictMode {
		mode = policy.ModeCI
	}

	// Evaluate against policy
	evalInput := usecases.EvaluatePolicyInput{
		Assessment: scanOutput.Assessment,
		Policy:     &pol,
		Baseline:   bl,
		Mode:       mode,
	}
	evalOutput := evalUseCase.Execute(evalInput)

	// Write output
	if summaryOnly {
		if err := writer.WriteSummary(scanOutput.Assessment, evalOutput.Result); err != nil {
			return fmt.Errorf("failed to write summary: %w", err)
		}
	} else {
		if err := writer.WriteAssessment(scanOutput.Assessment, evalOutput.Result); err != nil {
			return fmt.Errorf("failed to write assessment: %w", err)
		}
	}

	// Determine exit code
	code := exitcode.FromDecision(evalOutput.Decision, strictMode || cfg.Policy.BaselineMode == "strict")

	if code != exitcode.Success {
		os.Exit(code)
	}

	return nil
}

// determineEngines returns which engines to run based on config and flags
func determineEngines(cfg *config.Config) []string {
	var engineIDs []string

	// If include list is specified, use only those
	if len(includeEngines) > 0 {
		return includeEngines
	}

	// Get enabled engines from config
	if cfg.Engines.Gosec.Enabled {
		engineIDs = append(engineIDs, "gosec")
	}
	if cfg.Engines.Govulncheck.Enabled {
		engineIDs = append(engineIDs, "govulncheck")
	}
	if cfg.Engines.Gitleaks.Enabled {
		engineIDs = append(engineIDs, "gitleaks")
	}
	if cfg.Engines.CycloneDX.Enabled {
		engineIDs = append(engineIDs, "cyclonedx-gomod")
	}

	// Apply exclusions
	if len(excludeEngines) > 0 {
		filtered := make([]string, 0, len(engineIDs))
		for _, id := range engineIDs {
			excluded := false
			for _, ex := range excludeEngines {
				if id == ex {
					excluded = true
					break
				}
			}
			if !excluded {
				filtered = append(filtered, id)
			}
		}
		engineIDs = filtered
	}

	return engineIDs
}

// applyThresholdOverrides applies threshold overrides from flags
func applyThresholdOverrides(cfg *config.Config) {
	if failThreshold != "" {
		cfg.Policy.Threshold.FailOn = failThreshold
	}
	if warnThreshold != "" {
		cfg.Policy.Threshold.WarnOn = warnThreshold
	}
}

// getModeString returns "ci" if strict mode, otherwise "local"
func getModeString() string {
	if strictMode {
		return "ci"
	}
	return "local"
}

// runWatchMode runs the scan in watch mode, re-running on file changes.
func runWatchMode(ctx context.Context, cfg *config.Config, target string, writer ports.ArtifactWriter) error {
	_ = writer.WriteProgress("Starting watch mode...")
	_ = writer.WriteProgress(fmt.Sprintf("Watching for changes in %s (Ctrl+C to exit)", target))
	_ = writer.WriteProgress("")

	// Run initial scan
	runSingleScan(ctx, cfg, target, writer)

	// Create watcher config
	watchCfg := watcher.Config{
		Root:       target,
		Extensions: []string{".go", ".mod", ".sum"},
		Exclude:    []string{"vendor/", "testdata/", ".git/", "_test.go"},
		Debounce:   watchDebounce,
		OnChange: func(events []watcher.Event) {
			// Clear screen for fresh output
			fmt.Print("\033[H\033[2J")

			// Show changed files
			_ = writer.WriteProgress(fmt.Sprintf("[%s] Detected %d file change(s):",
				time.Now().Format("15:04:05"), len(events)))
			for _, e := range events {
				_ = writer.WriteProgress(fmt.Sprintf("  %s: %s", e.Operation, e.Path))
			}
			_ = writer.WriteProgress("")

			// Re-run scan
			runSingleScan(ctx, cfg, target, writer)
		},
	}

	w := watcher.New(watchCfg)
	if err := w.Start(); err != nil {
		return fmt.Errorf("failed to start watcher: %w", err)
	}

	// Wait for context cancellation
	<-ctx.Done()
	w.Stop()

	_ = writer.WriteProgress("\nWatch mode stopped")
	return nil
}

// runSingleScan executes a single scan run.
func runSingleScan(ctx context.Context, cfg *config.Config, target string, writer ports.ArtifactWriter) {
	_ = writer.WriteProgress(fmt.Sprintf("[%s] Running security scan...", time.Now().Format("15:04:05")))

	// Create engine registry
	registry := engines.NewDefaultRegistry()

	// Create composite normalizer
	normalizer := engines.NewCompositeNormalizer()

	// Create run scan use case
	scanUseCase := usecases.NewRunScanUseCase(registry, normalizer, writer)

	// Determine which engines to run
	engineIDs := determineEngines(cfg)

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
		_ = writer.WriteError(fmt.Errorf("scan failed: %w", err))
		return
	}

	// Load baseline if specified
	var bl *domainBaseline.Baseline
	if baselinePath != "" || cfg.Baseline.Path != "" {
		blPath := baselinePath
		if blPath == "" {
			blPath = cfg.Baseline.Path
		}

		store := baseline.NewStoreWithPath(blPath)
		bl, err = store.Load()
		if err != nil {
			bl = domainBaseline.NewBaseline("")
		}
	} else {
		bl = domainBaseline.NewBaseline("")
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

	// Evaluate against policy
	evalInput := usecases.EvaluatePolicyInput{
		Assessment: scanOutput.Assessment,
		Policy:     &pol,
		Baseline:   bl,
		Mode:       mode,
	}
	evalOutput := evalUseCase.Execute(evalInput)

	// Write output
	if summaryOnly {
		_ = writer.WriteSummary(scanOutput.Assessment, evalOutput.Result)
	} else {
		_ = writer.WriteAssessment(scanOutput.Assessment, evalOutput.Result)
	}

	// Show press any key hint
	_ = writer.WriteProgress("")
	_ = writer.WriteProgress("Watching for file changes... (Ctrl+C to exit)")
}
