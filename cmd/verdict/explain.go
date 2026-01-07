package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/ai"
	"github.com/spf13/cobra"
)

var (
	explainProvider string
	explainWithCode bool
)

// explainCmd explains a security finding using AI
var explainCmd = &cobra.Command{
	Use:   "explain <finding-id>",
	Short: "Explain a security finding using AI",
	Long: `Use AI to generate a detailed explanation of a security finding.

This command provides:
  - A brief summary of what the finding means
  - Detailed explanation of why it's a security concern
  - The potential risk and impact if exploited
  - References to relevant security documentation

The finding-id can be obtained from a previous scan's JSON output.

Examples:
  verdict explain finding-abc123
  verdict explain finding-abc123 --provider claude
  verdict explain finding-abc123 --json`,
	Args: cobra.ExactArgs(1),
	RunE: runExplain,
}

func init() {
	explainCmd.Flags().StringVar(&explainProvider, "provider", "", "AI provider to use (default: from config)")
	explainCmd.Flags().BoolVar(&explainWithCode, "with-code", false, "include code suggestions")

	rootCmd.AddCommand(explainCmd)
}

func runExplain(cmd *cobra.Command, args []string) error {
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

	findingID := args[0]

	// For now, create a placeholder finding from the ID
	// In a real implementation, we'd load the finding from a scan result
	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"unknown",
		findingID,
		"Finding " + findingID,
		finding.SeverityMedium,
		finding.NewLocationSimple("unknown", 0),
		finding.WithDescription("Finding loaded by ID: "+findingID),
	)

	// Create advisor
	advisorConfig := cfg.ToAdvisorConfig()
	advisor := ai.NewAdvisor(advisorConfig)

	if !advisor.IsAvailable() {
		return fmt.Errorf("AI advisor is not available. Check your ANTHROPIC_API_KEY environment variable")
	}

	// Generate explanation
	fmt.Printf("Generating explanation for %s using %s...\n\n", findingID, advisor.Provider())

	var explanation any
	var explainErr error

	if explainProvider != "" {
		explanation, explainErr = advisor.ExplainWithProvider(ctx, f, explainProvider)
	} else {
		explanation, explainErr = advisor.Explain(ctx, f)
	}

	if explainErr != nil {
		return fmt.Errorf("failed to generate explanation: %w", explainErr)
	}

	// Output result
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(explanation)
	}

	// Console output
	fmt.Println(explanation)
	return nil
}
