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
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/github"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/writers"
	"github.com/felixgeelhaar/verdictsec/pkg/exitcode"
	"github.com/spf13/cobra"
)

var (
	prNumber   int
	prRepo     string
	prToken    string
	prAnnotate bool
)

// ciCmd performs a CI-mode security scan with strict settings
var ciCmd = &cobra.Command{
	Use:   "ci [path]",
	Short: "Run security scan in CI mode (strict)",
	Long: `Run a comprehensive security scan in CI mode with strict settings.

CI mode:
  - Fails on warnings (equivalent to --strict)
  - Uses JSON output format by default when in non-interactive mode
  - Exits with non-zero code on any policy violation

PR Annotations:
  - Use --pr <number> to post findings as inline review comments
  - Findings are filtered to only files changed in the PR
  - Critical/High findings trigger REQUEST_CHANGES review
  - Requires GITHUB_TOKEN environment variable

Examples:
  verdict ci                       # Scan current directory
  verdict ci ./myproject           # Scan specific path
  verdict ci --json                # Force JSON output
  verdict ci --pr 123              # Post findings to PR #123
  verdict ci --pr 123 --repo owner/repo   # Explicit repository`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCI,
}

func init() {
	// PR annotation flags
	ciCmd.Flags().IntVar(&prNumber, "pr", 0, "PR number to annotate with findings")
	ciCmd.Flags().StringVar(&prRepo, "repo", "", "repository in owner/repo format (default: GITHUB_REPOSITORY)")
	ciCmd.Flags().StringVar(&prToken, "token", "", "GitHub token (default: GITHUB_TOKEN)")
	ciCmd.Flags().BoolVar(&prAnnotate, "annotate", true, "post inline comments (use --annotate=false for summary only)")

	rootCmd.AddCommand(ciCmd)
}

func runCI(cmd *cobra.Command, args []string) error {
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

	// CI mode is always strict
	cfg.Policy.BaselineMode = "strict"

	// Create writer (may be GitHub PR writer if --pr is specified)
	writer, err := createCIWriter(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to create writer: %w", err)
	}

	// Get target path
	target := getTarget(args)

	_ = writer.WriteProgress(fmt.Sprintf("Starting CI security scan of %s", target))

	// Create engine registry
	registry := engines.NewDefaultRegistry()

	// Warn about missing engines
	portsCfg := cfg.ToPortsConfig()
	WarnMissingEngines(registry, portsCfg)

	// Create composite normalizer
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
	if cfg.Engines.CycloneDX.Enabled {
		engineIDs = append(engineIDs, ports.EngineCycloneDX)
	}

	_ = writer.WriteProgress(fmt.Sprintf("Running %d engine(s) in CI mode", len(engineIDs)))

	// Execute scan
	scanInput := usecases.RunScanInput{
		Target:     ports.NewTarget(target),
		Config:     cfg.ToPortsConfig(),
		Mode:       "ci",
		Engines:    engineIDs,
		Parallel:   true,
		MaxWorkers: 4,
	}

	scanOutput, err := scanUseCase.Execute(ctx, scanInput)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Load baseline if configured
	var bl *domainBaseline.Baseline
	if cfg.Baseline.Path != "" {
		store := baseline.NewStoreWithPath(cfg.Baseline.Path)
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
	evalUseCase := usecases.NewEvaluatePolicyUseCase(nil)

	// Build policy
	pol := cfg.ToDomainPolicy()

	// Evaluate against policy (CI mode = strict)
	evalInput := usecases.EvaluatePolicyInput{
		Assessment: scanOutput.Assessment,
		Policy:     &pol,
		Baseline:   bl,
		Mode:       policy.ModeCI,
	}
	evalOutput := evalUseCase.Execute(ctx, evalInput)

	// Write output
	if err := writer.WriteAssessment(scanOutput.Assessment, evalOutput.Result); err != nil {
		return fmt.Errorf("failed to write assessment: %w", err)
	}

	// CI mode always uses strict exit codes
	code := exitcode.FromDecision(evalOutput.Decision, true)

	if code != exitcode.Success {
		os.Exit(code)
	}

	return nil
}

// createCIWriter creates a writer for CI mode, which may be a GitHub PR writer.
func createCIWriter(ctx context.Context, cfg *config.Config) (ports.ArtifactWriter, error) {
	// If --pr is specified, use GitHub PR writer
	if prNumber > 0 {
		// Auto-detect PR number from GitHub Actions if not specified
		prNum := prNumber
		if prNum == 0 {
			var err error
			prNum, err = github.GetPRNumber()
			if err != nil {
				return nil, fmt.Errorf("PR number not specified and could not be detected: %w", err)
			}
		}

		repo := prRepo
		if repo == "" {
			repo = github.GetRepository()
		}

		prWriter, err := writers.NewGitHubPRWriter(ctx, writers.GitHubPRWriterConfig{
			Token:      prToken,
			Repository: repo,
			PRNumber:   prNum,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub PR writer: %w", err)
		}

		return prWriter, nil
	}

	// Default to standard writer
	return createWriter(cfg)
}
