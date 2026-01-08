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
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/providers"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/writers"
	"github.com/felixgeelhaar/verdictsec/pkg/exitcode"
	"github.com/spf13/cobra"
)

var (
	prNumber   int
	prRepo     string
	prToken    string
	prAnnotate bool
	prProvider string
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

PR Annotations (GitHub, GitLab, Bitbucket):
  - Use --pr <number> to post findings as inline review comments
  - Provider auto-detection: GitHub Actions, GitLab CI, Bitbucket Pipelines
  - Findings are filtered to only files changed in the PR/MR
  - Critical/High findings trigger REQUEST_CHANGES (GitHub) or blocking (others)

Environment Variables:
  GitHub:    GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_PR_NUMBER
  GitLab:    GITLAB_TOKEN (or CI_JOB_TOKEN), CI_PROJECT_PATH, CI_MERGE_REQUEST_IID
  Bitbucket: BITBUCKET_TOKEN, BITBUCKET_WORKSPACE, BITBUCKET_REPO_SLUG, BITBUCKET_PR_ID

Examples:
  verdict ci                              # Scan current directory
  verdict ci ./myproject                  # Scan specific path
  verdict ci --json                       # Force JSON output
  verdict ci --pr 123                     # Post findings to PR #123 (auto-detect provider)
  verdict ci --pr 123 --provider=github   # Explicit GitHub
  verdict ci --pr 123 --provider=gitlab   # GitLab MR annotations
  verdict ci --pr 123 --provider=bitbucket # Bitbucket PR comments`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCI,
}

func init() {
	// PR annotation flags
	ciCmd.Flags().IntVar(&prNumber, "pr", 0, "PR/MR number to annotate with findings")
	ciCmd.Flags().StringVar(&prRepo, "repo", "", "repository in owner/repo format (auto-detected in CI)")
	ciCmd.Flags().StringVar(&prToken, "token", "", "API token (auto-detected from environment)")
	ciCmd.Flags().BoolVar(&prAnnotate, "annotate", true, "post inline comments (use --annotate=false for summary only)")
	ciCmd.Flags().StringVar(&prProvider, "provider", "auto", "CI provider: auto, github, gitlab, bitbucket")

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

// createCIWriter creates a writer for CI mode, which may be a PR writer for various providers.
func createCIWriter(ctx context.Context, cfg *config.Config) (ports.ArtifactWriter, error) {
	// If --pr is specified, use PR writer with appropriate provider
	if prNumber > 0 {
		provider, err := createPRProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create PR provider: %w", err)
		}

		prWriter, err := writers.NewPRWriter(ctx, provider)
		if err != nil {
			return nil, fmt.Errorf("failed to create PR writer: %w", err)
		}

		return prWriter, nil
	}

	// Default to standard writer
	return createWriter(cfg)
}

// createPRProvider creates a PR provider based on the --provider flag or auto-detection.
func createPRProvider() (providers.PRProvider, error) {
	factory := providers.NewFactory()

	// Parse provider name
	providerName, err := providers.ParseProviderName(prProvider)
	if err != nil {
		return nil, err
	}

	// Auto-detect if not specified
	if providerName == "" {
		provider, err := factory.DetectProvider()
		if err != nil {
			// If auto-detection fails, try to create based on available env vars
			return nil, fmt.Errorf("provider auto-detection failed: %w (use --provider to specify explicitly)", err)
		}

		// Override PR number if specified via flag
		if prNumber > 0 {
			// Need to create a new provider with the explicit PR number
			config := providers.ProviderConfig{
				Token:      prToken,
				Repository: prRepo,
				PRNumber:   prNumber,
			}
			return factory.CreateProvider(provider.Name(), config)
		}

		return provider, nil
	}

	// Create explicit provider
	config := providers.ProviderConfig{
		Token:      prToken,
		Repository: prRepo,
		PRNumber:   prNumber,
	}

	return factory.CreateProvider(providerName, config)
}
