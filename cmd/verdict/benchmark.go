package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/writers"
	"github.com/spf13/cobra"
)

var (
	benchIterations int
	benchWarmup     int
	benchOutputJSON bool
	benchEnginesOnly bool
)

// benchmarkCmd performs performance benchmarking of security scans
var benchmarkCmd = &cobra.Command{
	Use:   "benchmark [path]",
	Short: "Benchmark scan performance",
	Long: `Run multiple scan iterations to benchmark performance.

This command executes multiple security scans and collects timing statistics
to help understand and optimize scan performance.

Outputs:
  - Per-engine execution times (min, max, mean, p50, p95, p99)
  - Overall scan times
  - Memory usage (if available)

Examples:
  verdict benchmark                    # Benchmark current directory (5 iterations)
  verdict benchmark -n 10              # Run 10 iterations
  verdict benchmark --warmup 2         # Run 2 warmup iterations first
  verdict benchmark --json             # Output as JSON for CI integration
  verdict benchmark --engines-only     # Only show per-engine breakdown`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBenchmark,
}

func init() {
	benchmarkCmd.Flags().IntVarP(&benchIterations, "iterations", "n", 5, "number of benchmark iterations")
	benchmarkCmd.Flags().IntVar(&benchWarmup, "warmup", 1, "number of warmup iterations (not included in stats)")
	benchmarkCmd.Flags().BoolVar(&benchOutputJSON, "json", false, "output results as JSON")
	benchmarkCmd.Flags().BoolVar(&benchEnginesOnly, "engines-only", false, "only show per-engine breakdown")
	benchmarkCmd.Flags().StringSliceVar(&excludeEngines, "exclude", nil, "engines to exclude")
	benchmarkCmd.Flags().StringSliceVar(&includeEngines, "include", nil, "engines to include (only these will run)")

	rootCmd.AddCommand(benchmarkCmd)
}

// BenchmarkResult holds the results of a benchmark run.
type BenchmarkResult struct {
	Target        string                   `json:"target"`
	Iterations    int                      `json:"iterations"`
	WarmupRuns    int                      `json:"warmup_runs"`
	TotalDuration time.Duration            `json:"total_duration"`
	EngineResults map[string]*EngineResult `json:"engine_results"`
	OverallStats  *Stats                   `json:"overall_stats"`
}

// EngineResult holds results for a single engine.
type EngineResult struct {
	EngineID    string        `json:"engine_id"`
	Available   bool          `json:"available"`
	Timings     []time.Duration `json:"-"` // Raw timings
	Stats       *Stats        `json:"stats,omitempty"`
}

// Stats holds statistical information about timings.
type Stats struct {
	Min     time.Duration `json:"min"`
	Max     time.Duration `json:"max"`
	Mean    time.Duration `json:"mean"`
	P50     time.Duration `json:"p50"`
	P95     time.Duration `json:"p95"`
	P99     time.Duration `json:"p99"`
	StdDev  time.Duration `json:"std_dev"`
}

func runBenchmark(cmd *cobra.Command, args []string) error {
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

	// Initialize result
	result := &BenchmarkResult{
		Target:        target,
		Iterations:    benchIterations,
		WarmupRuns:    benchWarmup,
		EngineResults: make(map[string]*EngineResult),
	}

	// Create engine registry
	registry := engines.NewDefaultRegistry()

	// Determine which engines to run
	engineIDs := determineEngines(cfg)

	// Initialize engine results
	for _, id := range engineIDs {
		engine, found := registry.Get(ports.EngineID(id))
		result.EngineResults[id] = &EngineResult{
			EngineID:  id,
			Available: found && engine.IsAvailable(),
			Timings:   make([]time.Duration, 0, benchIterations),
		}
	}

	if !benchOutputJSON {
		fmt.Println("VerdictSec Benchmark")
		fmt.Println("====================")
		fmt.Printf("Target: %s\n", target)
		fmt.Printf("Engines: %v\n", engineIDs)
		fmt.Printf("Iterations: %d (+ %d warmup)\n", benchIterations, benchWarmup)
		fmt.Println()
	}

	// Run warmup iterations
	if benchWarmup > 0 && !benchOutputJSON {
		fmt.Printf("Running %d warmup iteration(s)...\n", benchWarmup)
	}
	for i := 0; i < benchWarmup; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = runBenchmarkIteration(ctx, cfg, target, registry, nil)
	}

	// Collect overall timings
	overallTimings := make([]time.Duration, 0, benchIterations)

	// Run benchmark iterations
	startTime := time.Now()
	for i := 0; i < benchIterations; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !benchOutputJSON {
			fmt.Printf("\rIteration %d/%d...", i+1, benchIterations)
		}

		iterStart := time.Now()
		engineTimings := runBenchmarkIteration(ctx, cfg, target, registry, engineIDs)
		iterDuration := time.Since(iterStart)

		overallTimings = append(overallTimings, iterDuration)

		// Store per-engine timings
		for engineID, timing := range engineTimings {
			if er, ok := result.EngineResults[engineID]; ok {
				er.Timings = append(er.Timings, timing)
			}
		}
	}

	result.TotalDuration = time.Since(startTime)

	if !benchOutputJSON {
		fmt.Println("\r                        ") // Clear progress line
		fmt.Println()
	}

	// Calculate statistics
	result.OverallStats = calculateStats(overallTimings)

	for _, er := range result.EngineResults {
		if len(er.Timings) > 0 {
			er.Stats = calculateStats(er.Timings)
		}
	}

	// Output results
	if benchOutputJSON {
		return outputBenchmarkJSON(result)
	}

	return outputBenchmarkText(result)
}

// runBenchmarkIteration runs a single scan iteration and returns per-engine timings.
func runBenchmarkIteration(
	ctx context.Context,
	cfg *config.Config,
	target string,
	registry *engines.Registry,
	engineIDs []string,
) map[string]time.Duration {
	timings := make(map[string]time.Duration)

	// Create normalizer and use case (silently)
	normalizer := engines.NewCompositeNormalizer()

	// Use a silent writer
	writer := writers.NewSilentWriter()

	scanUseCase := usecases.NewRunScanUseCase(registry, normalizer, writer)

	// Convert to ports.EngineID
	var portsEngineIDs []ports.EngineID
	for _, id := range engineIDs {
		portsEngineIDs = append(portsEngineIDs, ports.EngineID(id))
	}

	// Execute scan with timing
	scanInput := usecases.RunScanInput{
		Target:     ports.NewTarget(target),
		Config:     cfg.ToPortsConfig(),
		Mode:       "benchmark",
		Engines:    portsEngineIDs,
		Parallel:   false, // Run sequentially to get accurate per-engine timings
		MaxWorkers: 1,
	}

	// Track individual engine times
	for _, id := range engineIDs {
		engine, found := registry.Get(ports.EngineID(id))
		if !found || !engine.IsAvailable() {
			continue
		}

		start := time.Now()
		_, _, _ = engine.Run(ctx, ports.NewTarget(target), cfg.ToPortsConfig().Engines[ports.EngineID(id)])
		timings[id] = time.Since(start)
	}

	// Also run the full scan to account for orchestration overhead
	_, _ = scanUseCase.Execute(ctx, scanInput)

	return timings
}

// calculateStats computes statistics for a set of timings.
func calculateStats(timings []time.Duration) *Stats {
	if len(timings) == 0 {
		return nil
	}

	// Sort for percentiles
	sorted := make([]time.Duration, len(timings))
	copy(sorted, timings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	// Calculate mean
	var sum time.Duration
	for _, t := range timings {
		sum += t
	}
	mean := sum / time.Duration(len(timings))

	// Calculate std dev
	var variance float64
	for _, t := range timings {
		diff := float64(t - mean)
		variance += diff * diff
	}
	variance /= float64(len(timings))
	stdDev := time.Duration(variance)

	return &Stats{
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
		Mean:   mean,
		P50:    percentile(sorted, 50),
		P95:    percentile(sorted, 95),
		P99:    percentile(sorted, 99),
		StdDev: stdDev,
	}
}

// percentile returns the p-th percentile from a sorted slice.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// outputBenchmarkJSON outputs results as JSON.
func outputBenchmarkJSON(result *BenchmarkResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// outputBenchmarkText outputs results as formatted text.
func outputBenchmarkText(result *BenchmarkResult) error {
	fmt.Println("Results")
	fmt.Println("-------")
	fmt.Printf("Total benchmark time: %v\n", result.TotalDuration.Round(time.Millisecond))
	fmt.Println()

	if !benchEnginesOnly && result.OverallStats != nil {
		fmt.Println("Overall Scan Statistics:")
		fmt.Printf("  Min:    %v\n", result.OverallStats.Min.Round(time.Millisecond))
		fmt.Printf("  Max:    %v\n", result.OverallStats.Max.Round(time.Millisecond))
		fmt.Printf("  Mean:   %v\n", result.OverallStats.Mean.Round(time.Millisecond))
		fmt.Printf("  P50:    %v\n", result.OverallStats.P50.Round(time.Millisecond))
		fmt.Printf("  P95:    %v\n", result.OverallStats.P95.Round(time.Millisecond))
		fmt.Printf("  P99:    %v\n", result.OverallStats.P99.Round(time.Millisecond))
		fmt.Println()
	}

	fmt.Println("Per-Engine Statistics:")
	fmt.Printf("%-20s %10s %10s %10s %10s %10s\n", "Engine", "Min", "Max", "Mean", "P50", "P95")
	fmt.Println(repeatString("-", 75))

	// Sort engines for consistent output
	var engineIDs []string
	for id := range result.EngineResults {
		engineIDs = append(engineIDs, id)
	}
	sort.Strings(engineIDs)

	for _, id := range engineIDs {
		er := result.EngineResults[id]
		if !er.Available {
			fmt.Printf("%-20s %10s\n", id, "(not available)")
			continue
		}
		if er.Stats == nil {
			fmt.Printf("%-20s %10s\n", id, "(no data)")
			continue
		}

		fmt.Printf("%-20s %10v %10v %10v %10v %10v\n",
			id,
			er.Stats.Min.Round(time.Millisecond),
			er.Stats.Max.Round(time.Millisecond),
			er.Stats.Mean.Round(time.Millisecond),
			er.Stats.P50.Round(time.Millisecond),
			er.Stats.P95.Round(time.Millisecond),
		)
	}

	return nil
}

// repeatString repeats a string n times.
func repeatString(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
