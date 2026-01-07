package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/ai"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/spf13/cobra"
)

var (
	aiProvider   string
	aiScanFile   string
)

// aiCmd is the parent command for AI operations
var aiCmd = &cobra.Command{
	Use:   "ai",
	Short: "AI-powered security advisory features",
	Long: `AI-powered security advisory features for VerdictSec.

These features use AI to provide:
  - Explanations of security findings
  - Remediation suggestions with code examples
  - Security posture summaries

AI features are advisory-only and cannot modify findings, decisions, or policy.
Enable AI features by setting ai.enabled: true in your config.

Examples:
  verdict ai summarize                  # Summarize current scan
  verdict ai summarize --scan results.json  # Summarize from file`,
}

// aiSummarizeCmd generates a posture summary
var aiSummarizeCmd = &cobra.Command{
	Use:   "summarize [path]",
	Short: "Generate a security posture summary",
	Long: `Use AI to generate an executive summary of the security posture.

This command provides:
  - An overall security rating (excellent/good/fair/poor/critical)
  - A numeric score (0-100)
  - Key security highlights and concerns
  - Recommendations for improvement
  - Category-wise breakdown

Examples:
  verdict ai summarize                      # Scan current directory and summarize
  verdict ai summarize ./myproject          # Scan specific directory
  verdict ai summarize --scan results.json  # Summarize from existing scan`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAISummarize,
}

// aiStatusCmd shows AI configuration status
var aiStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show AI configuration status",
	Long: `Show the current AI configuration and availability status.

This helps diagnose issues with AI features:
  - Whether AI is enabled in config
  - Which provider is configured
  - Whether the API key is set
  - Which features are enabled`,
	RunE: runAIStatus,
}

func init() {
	// AI summarize flags
	aiSummarizeCmd.Flags().StringVar(&aiProvider, "provider", "", "AI provider to use (default: from config)")
	aiSummarizeCmd.Flags().StringVar(&aiScanFile, "scan", "", "use existing scan results file instead of scanning")

	// Add subcommands
	aiCmd.AddCommand(aiSummarizeCmd)
	aiCmd.AddCommand(aiStatusCmd)

	rootCmd.AddCommand(aiCmd)
}

func runAISummarize(cmd *cobra.Command, args []string) error {
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

	// Check if AI is enabled
	if !cfg.AI.Enabled {
		return fmt.Errorf("AI features are not enabled. Set ai.enabled: true in your config")
	}

	// Create advisor
	advisorConfig := cfg.ToAdvisorConfig()
	advisor := ai.NewAdvisor(advisorConfig)

	if !advisor.IsAvailable() {
		return fmt.Errorf("AI advisor is not available. Check your ANTHROPIC_API_KEY environment variable")
	}

	// Get or run scan
	var assessment any

	if aiScanFile != "" {
		// TODO: Load assessment from file
		return fmt.Errorf("loading from scan file not yet implemented")
	}

	// Run a fresh scan
	target := getTarget(args)

	// Create writer
	writer, err := createWriter(cfg)
	if err != nil {
		return fmt.Errorf("failed to create writer: %w", err)
	}

	_ = writer.WriteProgress(fmt.Sprintf("Scanning %s for AI summary...", target))

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

	assessment = scanOutput.Assessment

	// Generate summary
	fmt.Printf("\nGenerating AI summary using %s...\n\n", advisor.Provider())

	var summary any
	var summaryErr error

	if aiProvider != "" {
		summary, summaryErr = advisor.SummarizeWithProvider(ctx, scanOutput.Assessment, aiProvider)
	} else {
		summary, summaryErr = advisor.Summarize(ctx, scanOutput.Assessment)
	}

	_ = assessment // Used for future file loading

	if summaryErr != nil {
		return fmt.Errorf("failed to generate summary: %w", summaryErr)
	}

	// Output result
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	}

	// Console output
	fmt.Println(summary)
	return nil
}

func runAIStatus(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	fmt.Println("AI Configuration Status")
	fmt.Println("=======================")
	fmt.Printf("Enabled:   %t\n", cfg.AI.Enabled)
	fmt.Printf("Provider:  %s\n", cfg.AI.Provider)
	fmt.Printf("Model:     %s\n", cfg.AI.Model)
	fmt.Println("\nFeatures:")
	fmt.Printf("  Explain:   %t\n", cfg.AI.Features.Explain)
	fmt.Printf("  Remediate: %t\n", cfg.AI.Features.Remediate)
	fmt.Printf("  Summarize: %t\n", cfg.AI.Features.Summarize)

	// Check API key availability
	fmt.Println("\nAvailability:")
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		fmt.Println("  ANTHROPIC_API_KEY: set")
	} else {
		fmt.Println("  ANTHROPIC_API_KEY: not set")
	}
	if os.Getenv("OPENAI_API_KEY") != "" {
		fmt.Println("  OPENAI_API_KEY: set")
	} else {
		fmt.Println("  OPENAI_API_KEY: not set")
	}

	// Test availability
	if cfg.AI.Enabled {
		advisorConfig := cfg.ToAdvisorConfig()
		advisor := ai.NewAdvisor(advisorConfig)
		if advisor.IsAvailable() {
			fmt.Println("\nStatus: Ready")
		} else {
			fmt.Println("\nStatus: Not available (check API key)")
		}
	} else {
		fmt.Println("\nStatus: Disabled (set ai.enabled: true to enable)")
	}

	return nil
}
