package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	domainBaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/workspace"
	"github.com/felixgeelhaar/verdictsec/pkg/exitcode"
	"github.com/spf13/cobra"
)

var (
	monorepoModules     []string
	monorepoFilter      string
	monorepoByModule    bool
	monorepoMaxWorkers  int
)

// monorepoCmd scans multiple Go modules in a monorepo.
var monorepoCmd = &cobra.Command{
	Use:   "monorepo [path]",
	Short: "Scan multiple Go modules in a monorepo",
	Long: `Scan all Go modules in a monorepo concurrently.

This command automatically discovers Go modules (directories containing go.mod)
and scans each one in parallel, then aggregates the results.

Examples:
  verdict monorepo                           # Scan all modules in current directory
  verdict monorepo ./workspace               # Scan modules in workspace
  verdict monorepo --modules=./svc/a,./svc/b # Scan specific modules only
  verdict monorepo --filter="services/*"     # Scan modules matching pattern
  verdict monorepo --by-module               # Show findings grouped by module
  verdict monorepo --workers=8               # Use 8 parallel workers`,
	Args: cobra.MaximumNArgs(1),
	RunE: runMonorepo,
}

func init() {
	monorepoCmd.Flags().StringSliceVar(&monorepoModules, "modules", nil, "specific modules to scan (comma-separated paths)")
	monorepoCmd.Flags().StringVar(&monorepoFilter, "filter", "", "filter modules by path pattern (e.g., 'services/*')")
	monorepoCmd.Flags().BoolVar(&monorepoByModule, "by-module", false, "group output by module")
	monorepoCmd.Flags().IntVar(&monorepoMaxWorkers, "workers", 4, "number of parallel workers")

	rootCmd.AddCommand(monorepoCmd)
}

func runMonorepo(cmd *cobra.Command, args []string) error {
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

	// Get root path
	rootPath := "."
	if len(args) > 0 {
		rootPath = args[0]
	}

	_ = writer.WriteProgress(fmt.Sprintf("Discovering modules in %s...", rootPath))

	// Discover modules
	discovery := workspace.NewDiscovery(rootPath, workspace.DefaultDiscoveryOptions())
	modules, err := discovery.FindModules()
	if err != nil {
		return fmt.Errorf("failed to discover modules: %w", err)
	}

	if len(modules) == 0 {
		_ = writer.WriteProgress("No Go modules found.")
		return nil
	}

	// Filter to specific modules if requested
	if len(monorepoModules) > 0 {
		modules = filterModulesByPath(modules, monorepoModules)
	}

	_ = writer.WriteProgress(fmt.Sprintf("Found %d module(s):", len(modules)))
	for _, mod := range modules {
		_ = writer.WriteProgress(fmt.Sprintf("  - %s (%s)", mod.Path, mod.Name))
	}
	_ = writer.WriteProgress("")

	// Create engine registry
	registry := engines.NewDefaultRegistry()

	// Create composite normalizer
	normalizer := engines.NewCompositeNormalizer()

	// Determine which engines to run
	engineIDs := determineEngines(cfg)
	var portsEngineIDs []ports.EngineID
	for _, id := range engineIDs {
		portsEngineIDs = append(portsEngineIDs, ports.EngineID(id))
	}

	// Create scan function
	scanFn := func(ctx context.Context, target ports.Target) (*assessment.Assessment, error) {
		scanUseCase := usecases.NewRunScanUseCase(registry, normalizer, nil) // nil writer to suppress per-module output

		scanInput := usecases.RunScanInput{
			Target:     target,
			Config:     cfg.ToPortsConfig(),
			Mode:       getModeString(),
			Engines:    portsEngineIDs,
			Parallel:   true,
			MaxWorkers: 2, // Fewer workers per module since we're already parallel
		}

		output, err := scanUseCase.Execute(ctx, scanInput)
		if err != nil {
			return nil, err
		}
		return output.Assessment, nil
	}

	// Create parallel scanner with progress
	scanner := workspace.NewParallelScanner(
		workspace.WithMaxWorkers(monorepoMaxWorkers),
		workspace.WithProgress(func(mod workspace.Module, result *workspace.ModuleResult, completed, total int) {
			status := "✓"
			if result.Error != nil {
				status = "✗"
			}
			_ = writer.WriteProgress(fmt.Sprintf("[%d/%d] %s %s", completed, total, status, mod.Path))
		}),
	)

	// Run parallel scan
	_ = writer.WriteProgress(fmt.Sprintf("Scanning %d modules with %d workers...", len(modules), monorepoMaxWorkers))

	var results []workspace.ModuleResult
	if monorepoFilter != "" {
		results, err = scanner.ScanWithFilter(ctx, rootPath, modules, monorepoFilter, scanFn)
	} else {
		results, err = scanner.Scan(ctx, rootPath, modules, scanFn)
	}
	if err != nil {
		return fmt.Errorf("monorepo scan failed: %w", err)
	}

	// Aggregate results
	aggregated := workspace.Aggregate(results)

	_ = writer.WriteProgress("")
	_ = writer.WriteProgress(aggregated.Summary())
	_ = writer.WriteProgress("")

	// Load baseline
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

	// Build combined assessment
	combinedAssessment := buildCombinedAssessment(aggregated, rootPath)

	// Evaluate policy
	evalUseCase := usecases.NewEvaluatePolicyUseCase(nil)
	pol := cfg.ToDomainPolicy()

	mode := policy.ModeLocal
	if strictMode {
		mode = policy.ModeCI
	}

	evalInput := usecases.EvaluatePolicyInput{
		Assessment: combinedAssessment,
		Policy:     &pol,
		Baseline:   bl,
		Mode:       mode,
	}
	evalOutput := evalUseCase.Execute(ctx, evalInput)

	// Write output
	if monorepoByModule {
		writeByModuleOutput(writer, aggregated, evalOutput.Result)
	} else {
		if err := writer.WriteAssessment(combinedAssessment, evalOutput.Result); err != nil {
			return fmt.Errorf("failed to write assessment: %w", err)
		}
	}

	// Show failed modules
	if aggregated.HasErrors() {
		_ = writer.WriteProgress("\nFailed modules:")
		for _, mod := range aggregated.FailedModules {
			_ = writer.WriteProgress(fmt.Sprintf("  - %s", mod.Path))
		}
	}

	// Determine exit code
	code := exitcode.FromDecision(evalOutput.Decision, strictMode || cfg.Policy.BaselineMode == "strict")

	if code != exitcode.Success {
		os.Exit(code)
	}

	return nil
}

// filterModulesByPath filters modules to only those matching specified paths.
func filterModulesByPath(modules []workspace.Module, paths []string) []workspace.Module {
	pathSet := make(map[string]bool)
	for _, p := range paths {
		pathSet[p] = true
	}

	var filtered []workspace.Module
	for _, mod := range modules {
		if pathSet[mod.Path] || pathSet[mod.Name] {
			filtered = append(filtered, mod)
		}
	}
	return filtered
}

// buildCombinedAssessment creates a combined assessment from multiple module results.
func buildCombinedAssessment(agg *workspace.AggregatedResult, rootPath string) *assessment.Assessment {
	// Create a new assessment with all findings combined
	allFindings := agg.AllFindings()

	// Create assessment and add all findings
	assess := assessment.NewAssessment(rootPath)

	for _, f := range allFindings {
		assess.AddFinding(f)
	}

	assess.Complete()
	return assess
}

// writeByModuleOutput writes findings grouped by module.
func writeByModuleOutput(writer ports.ArtifactWriter, agg *workspace.AggregatedResult, _ interface{}) {
	for _, result := range agg.Modules {
		if result.Error != nil {
			continue
		}

		findings := agg.FindingsForModule(result.Module.Path)
		count := len(findings)

		if count == 0 {
			_ = writer.WriteProgress(fmt.Sprintf("\n%s: No findings", result.Module.Path))
			continue
		}

		_ = writer.WriteProgress(fmt.Sprintf("\n%s: %d finding(s)", result.Module.Path, count))

		for _, f := range findings {
			_ = writer.WriteProgress(fmt.Sprintf("  [%s] %s", f.EffectiveSeverity(), f.Title()))
			_ = writer.WriteProgress(fmt.Sprintf("    %s:%d", f.Location().File(), f.Location().Line()))
		}
	}
}
