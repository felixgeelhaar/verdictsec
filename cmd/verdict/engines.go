package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	domainBaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/pkg/exitcode"
	"github.com/spf13/cobra"
)

// sastCmd runs SAST (Static Application Security Testing) analysis
var sastCmd = &cobra.Command{
	Use:   "sast [path]",
	Short: "Run static analysis security testing",
	Long: `Run SAST using gosec to find security vulnerabilities in Go source code.

Examples:
  verdict sast                     # Scan current directory
  verdict sast ./myproject         # Scan specific path
  verdict sast --json              # Output as JSON`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSingleEngine(cmd, args, []ports.EngineID{ports.EngineGosec}, "SAST")
	},
}

// vulnCmd runs vulnerability scanning
var vulnCmd = &cobra.Command{
	Use:   "vuln [path]",
	Short: "Run vulnerability scan on dependencies",
	Long: `Run vulnerability scanning using govulncheck to find known vulnerabilities
in your Go dependencies.

Examples:
  verdict vuln                     # Scan current directory
  verdict vuln ./myproject         # Scan specific path
  verdict vuln --json              # Output as JSON`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSingleEngine(cmd, args, []ports.EngineID{ports.EngineGovulncheck}, "vulnerability")
	},
}

// secretsCmd runs secret detection
var secretsCmd = &cobra.Command{
	Use:   "secrets [path]",
	Short: "Detect secrets and credentials",
	Long: `Run secret detection using gitleaks to find hardcoded credentials,
API keys, and other sensitive data.

Examples:
  verdict secrets                  # Scan current directory
  verdict secrets ./myproject      # Scan specific path
  verdict secrets --json           # Output as JSON`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSingleEngine(cmd, args, []ports.EngineID{ports.EngineGitleaks}, "secrets")
	},
}

// sbomCmd generates Software Bill of Materials
var sbomCmd = &cobra.Command{
	Use:   "sbom [path]",
	Short: "Generate Software Bill of Materials",
	Long: `Generate an SBOM using cyclonedx-gomod to create a comprehensive
inventory of your project's dependencies.

Examples:
  verdict sbom                     # Generate for current directory
  verdict sbom ./myproject         # Generate for specific path
  verdict sbom --json              # Output as JSON`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSingleEngine(cmd, args, []ports.EngineID{ports.EngineCycloneDX}, "SBOM")
	},
}

func init() {
	rootCmd.AddCommand(sastCmd)
	rootCmd.AddCommand(vulnCmd)
	rootCmd.AddCommand(secretsCmd)
	rootCmd.AddCommand(sbomCmd)
}

// runSingleEngine runs a scan with specific engines
func runSingleEngine(cmd *cobra.Command, args []string, engineIDs []ports.EngineID, scanType string) error {
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

	_ = writer.WriteProgress(fmt.Sprintf("Starting %s scan of %s", scanType, target))

	// Create engine registry
	registry := engines.NewDefaultRegistry()

	// Create composite normalizer
	normalizer := engines.NewCompositeNormalizer()

	// Create run scan use case
	scanUseCase := usecases.NewRunScanUseCase(registry, normalizer, writer)

	// Execute scan
	scanInput := usecases.RunScanInput{
		Target:     ports.NewTarget(target),
		Config:     cfg.ToPortsConfig(),
		Mode:       getModeString(),
		Engines:    engineIDs,
		Parallel:   false, // Single engine, no need for parallel
		MaxWorkers: 1,
	}

	scanOutput, err := scanUseCase.Execute(ctx, scanInput)
	if err != nil {
		return fmt.Errorf("%s scan failed: %w", scanType, err)
	}

	// Load baseline if configured
	var bl *domainBaseline.Baseline
	if cfg.Baseline.Path != "" {
		store := baseline.NewStoreWithPath(cfg.Baseline.Path)
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
	if err := writer.WriteAssessment(scanOutput.Assessment, evalOutput.Result); err != nil {
		return fmt.Errorf("failed to write assessment: %w", err)
	}

	// Determine exit code
	code := exitcode.FromDecision(evalOutput.Decision, strictMode)

	if code != exitcode.Success {
		os.Exit(code)
	}

	return nil
}
