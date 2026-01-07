package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/writers"
	"github.com/felixgeelhaar/verdictsec/pkg/exitcode"
	"github.com/spf13/cobra"
)

var (
	diffNewOnly  bool
	diffRepoPath string
)

// diffCmd compares security findings between git refs
var diffCmd = &cobra.Command{
	Use:   "diff <from..to>",
	Short: "Compare security findings between git refs",
	Long: `Compare security findings between two git refs.

This command runs security scans on both refs and shows:
  - New findings (introduced in the 'to' ref)
  - Fixed findings (resolved since the 'from' ref)
  - Unchanged findings (present in both refs)

The ref range uses double-dot notation: from..to

Examples:
  verdict diff main..feature           # Compare branches
  verdict diff v1.0.0..v1.1.0          # Compare releases
  verdict diff HEAD~5..HEAD            # Last 5 commits
  verdict diff main..                  # main to HEAD
  verdict diff main..feature --new-only # Only show new findings
  verdict diff main..feature --json    # JSON output`,
	Args: cobra.ExactArgs(1),
	RunE: runDiff,
}

func init() {
	// Diff-specific flags
	diffCmd.Flags().BoolVar(&diffNewOnly, "new-only", false, "only show new findings")
	diffCmd.Flags().StringVar(&diffRepoPath, "repo", "", "repository path (default: current directory)")

	rootCmd.AddCommand(diffCmd)
}

func runDiff(cmd *cobra.Command, args []string) error {
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

	// Get repository path
	repoPath := diffRepoPath
	if repoPath == "" {
		repoPath, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
	}

	// Ref range from args
	refRange := args[0]

	// Write progress
	_ = writer.WriteProgress(fmt.Sprintf("Comparing security findings: %s", refRange))

	// Create engine registry
	registry := engines.NewDefaultRegistry()

	// Warn about missing engines
	portsCfg := cfg.ToPortsConfig()
	WarnMissingEngines(registry, portsCfg)

	// Create composite normalizer
	normalizer := engines.NewCompositeNormalizer()

	// Create scan use case
	scanUseCase := usecases.NewRunScanUseCase(registry, normalizer, nil)

	// Create diff refs use case
	diffUseCase := usecases.NewDiffRefsUseCase(scanUseCase, writer)

	// Determine which engines to run
	engineIDs := determineEngines(cfg)

	// Convert to ports.EngineID
	var portsEngineIDs []ports.EngineID
	for _, id := range engineIDs {
		portsEngineIDs = append(portsEngineIDs, ports.EngineID(id))
	}

	// Execute diff
	diffInput := usecases.DiffRefsInput{
		RepoPath: repoPath,
		RefRange: refRange,
		Config:   cfg.ToPortsConfig(),
		Engines:  portsEngineIDs,
		NewOnly:  diffNewOnly,
	}

	diffOutput, err := diffUseCase.Execute(ctx, diffInput)
	if err != nil {
		return fmt.Errorf("diff failed: %w", err)
	}

	// Write output based on format
	if jsonOutput {
		return writeDiffJSON(writer, diffOutput)
	}

	return writeDiffConsole(diffOutput, diffNewOnly)
}

// writeDiffConsole writes the diff output to the console.
func writeDiffConsole(output usecases.DiffRefsOutput, newOnly bool) error {
	// Color functions
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	if noColor {
		noColorFunc := func(a ...interface{}) string { return fmt.Sprint(a...) }
		red = noColorFunc
		green = noColorFunc
		blue = noColorFunc
		bold = noColorFunc
		dim = noColorFunc
	}

	// Header
	fmt.Println()
	fmt.Printf("%s\n", bold("Security Diff"))
	fmt.Printf("=====================================\n")
	fmt.Printf("Comparing: %s → %s\n", blue(output.FromRef), blue(output.ToRef))
	fmt.Println()

	// New findings
	if len(output.NewFindings) > 0 {
		fmt.Printf("%s %s (%d)\n", red("+"), bold("New Findings"), len(output.NewFindings))
		fmt.Println("-------------------------------------")
		for _, f := range output.NewFindings {
			writeFindingLine(f, "+", red, dim)
		}
		fmt.Println()
	}

	// Fixed findings (skip if new-only)
	if !newOnly && len(output.FixedFindings) > 0 {
		fmt.Printf("%s %s (%d)\n", green("-"), bold("Fixed Findings"), len(output.FixedFindings))
		fmt.Println("-------------------------------------")
		for _, f := range output.FixedFindings {
			writeFindingLine(f, "-", green, dim)
		}
		fmt.Println()
	}

	// Unchanged (skip if new-only or no verbose output)
	if !newOnly && verbosity == "verbose" && len(output.Unchanged) > 0 {
		fmt.Printf("%s %s (%d)\n", dim("="), bold("Unchanged"), len(output.Unchanged))
		fmt.Println("-------------------------------------")
		for _, f := range output.Unchanged {
			writeFindingLine(f, "=", dim, dim)
		}
		fmt.Println()
	}

	// Summary
	fmt.Println("=====================================")
	fmt.Printf("Summary: %s new, %s fixed, %s unchanged\n",
		red(fmt.Sprintf("+%d", output.Summary.TotalNew)),
		green(fmt.Sprintf("-%d", output.Summary.TotalFixed)),
		dim(fmt.Sprintf("=%d", output.Summary.TotalUnchanged)))

	// Net change
	netChange := output.NetChange()
	if netChange > 0 {
		fmt.Printf("Net: %s\n", red(fmt.Sprintf("+%d findings", netChange)))
	} else if netChange < 0 {
		fmt.Printf("Net: %s\n", green(fmt.Sprintf("%d findings", netChange)))
	} else {
		fmt.Printf("Net: %s\n", dim("no change"))
	}
	fmt.Println()

	// Exit code based on new findings
	if output.HasNewFindings() {
		os.Exit(exitcode.PolicyViolation)
	}

	return nil
}

// writeFindingLine writes a single finding line for diff output.
func writeFindingLine(f *finding.Finding, prefix string, colorFn, dimFn func(...interface{}) string) {
	sevStr := severityShort(f.EffectiveSeverity())
	loc := f.Location()
	fmt.Printf("  %s %s %s %s:%d\n",
		colorFn(prefix),
		sevStr,
		f.Title(),
		dimFn(loc.File()),
		loc.Line())
}

// severityShort returns a short colored severity string.
func severityShort(sev finding.Severity) string {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()

	if noColor {
		noColorFunc := func(a ...interface{}) string { return fmt.Sprint(a...) }
		red = noColorFunc
		yellow = noColorFunc
		blue = noColorFunc
	}

	switch sev {
	case finding.SeverityCritical:
		return red("[C]")
	case finding.SeverityHigh:
		return red("[H]")
	case finding.SeverityMedium:
		return yellow("[M]")
	case finding.SeverityLow:
		return blue("[L]")
	default:
		return "[?]"
	}
}

// writeDiffJSON writes the diff output as JSON.
func writeDiffJSON(writer ports.ArtifactWriter, output usecases.DiffRefsOutput) error {
	// Check if writer is a JSON writer with WriteDiff method
	if jsonWriter, ok := writer.(*writers.JSONWriter); ok {
		return jsonWriter.WriteDiff(writers.DiffInput{
			FromRef:       output.FromRef,
			ToRef:         output.ToRef,
			NewFindings:   output.NewFindings,
			FixedFindings: output.FixedFindings,
			Unchanged:     output.Unchanged,
		})
	}

	// Fallback: just write the 'to' assessment
	return writer.WriteAssessment(output.ToAssessment, services.EvaluationResult{})
}
