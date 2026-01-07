package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/ai"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/fixer"
	"github.com/spf13/cobra"
)

var (
	fixDryRun    bool
	fixNoConfirm bool
	fixRollback  bool
	fixList      bool
)

// fixCmd applies AI-generated fixes to security findings.
var fixCmd = &cobra.Command{
	Use:   "fix [finding-id]",
	Short: "Apply AI-generated fixes to security findings",
	Long: `Apply AI-generated code fixes to security findings.

This command uses the last scan results to look up findings and apply
AI-generated remediation suggestions. A backup is created before any
changes are made.

Prerequisites:
  - Run 'verdict scan' first to generate findings
  - Configure AI in .verdict/config.yaml (optional, for generating new remediations)

Examples:
  verdict fix                           # List fixable findings
  verdict fix finding-abc123            # Apply fix for a specific finding
  verdict fix finding-abc123 --dry-run  # Preview changes without applying
  verdict fix --rollback                # Restore from latest backup

Safety:
  - All changes are backed up to .verdict/backups/
  - Use --dry-run to preview changes
  - Use --rollback to undo changes
  - AI-generated fixes should be reviewed before committing`,
	Args: cobra.MaximumNArgs(1),
	RunE: runFix,
}

func init() {
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "preview changes without applying")
	fixCmd.Flags().BoolVar(&fixNoConfirm, "no-confirm", false, "skip confirmation prompt")
	fixCmd.Flags().BoolVar(&fixRollback, "rollback", false, "restore from latest backup")
	fixCmd.Flags().BoolVarP(&fixList, "list", "l", false, "list findings with fix status")

	rootCmd.AddCommand(fixCmd)
}

func runFix(cmd *cobra.Command, args []string) error {
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

	// Create store
	store := fixer.NewStore()

	// Check if scan results exist
	if !store.Exists() {
		return fmt.Errorf("no scan results found. Run 'verdict scan' first")
	}

	// Handle rollback
	if fixRollback {
		return runRollback(ctx)
	}

	// Handle list
	if fixList || len(args) == 0 {
		return runListFindings(ctx, store)
	}

	// Get finding ID
	findingID := args[0]

	// Create advisor if AI is enabled
	var advisor *ai.Advisor
	if cfg.AI.Enabled {
		advisor = ai.NewAdvisor(cfg.ToAdvisorConfig())
	}

	// Create use case
	useCase := usecases.NewApplyFixUseCase(store, advisor)

	// Check for uncommitted changes
	hasChanges, err := fixer.CheckGitStatus()
	if err == nil && hasChanges && !fixDryRun {
		fmt.Println("Warning: You have uncommitted changes in your repository.")
		fmt.Println("Consider committing or stashing them before applying fixes.")
		fmt.Println()
	}

	// Preview first
	preview, err := useCase.PreviewFix(ctx, usecases.PreviewFixInput{
		FindingID: findingID,
	})
	if err != nil {
		return err
	}

	// Display finding info
	fmt.Printf("Finding: %s\n", preview.Finding.Title())
	fmt.Printf("Severity: %s\n", preview.Finding.EffectiveSeverity())
	fmt.Printf("File: %s:%d\n", preview.Finding.Location().File(), preview.Finding.Location().Line())
	fmt.Println()

	// Display remediation info
	if preview.Remediation != nil {
		fmt.Printf("Remediation: %s\n", preview.Remediation.Summary())
		if preview.Remediation.Effort() != "" {
			fmt.Printf("Effort: %s\n", preview.Remediation.Effort())
		}
		fmt.Println()

		if len(preview.Remediation.Steps()) > 0 {
			fmt.Println("Steps:")
			for i, step := range preview.Remediation.Steps() {
				fmt.Printf("  %d. %s\n", i+1, step)
			}
			fmt.Println()
		}
	}

	// Display diffs
	if len(preview.Diffs) > 0 {
		fmt.Println("Proposed changes:")
		fmt.Println(strings.Repeat("-", 60))
		for _, diff := range preview.Diffs {
			fmt.Println(diff)
		}
		fmt.Println(strings.Repeat("-", 60))
		fmt.Println()
	} else {
		fmt.Println("No code changes available for this finding.")
		return nil
	}

	// Dry run stops here
	if fixDryRun {
		fmt.Println("Dry run complete. Use without --dry-run to apply changes.")
		return nil
	}

	// Confirm before applying
	if !fixNoConfirm {
		fmt.Print("Apply these changes? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Apply the fix
	result, err := useCase.Execute(ctx, usecases.ApplyFixInput{
		FindingID: findingID,
		DryRun:    false,
		NoConfirm: true, // Already confirmed above
	})
	if err != nil {
		return err
	}

	// Display results
	fmt.Println()
	fmt.Println(result.Message)

	for _, r := range result.Results {
		if r.Error != nil {
			fmt.Printf("  ✗ %s: %v\n", r.FilePath, r.Error)
		} else if r.Applied {
			fmt.Printf("  ✓ %s (backup: %s)\n", r.FilePath, r.BackupPath)
		}
	}

	fmt.Println()
	fmt.Println("Note: AI-generated fixes should be reviewed before committing.")
	fmt.Println("Use 'verdict fix --rollback' to undo changes if needed.")

	return nil
}

func runListFindings(ctx context.Context, store *fixer.Store) error {
	findings, hasRem, err := store.ListFindings()
	if err != nil {
		return err
	}

	if len(findings) == 0 {
		fmt.Println("No findings found. Run 'verdict scan' first.")
		return nil
	}

	fmt.Printf("Found %d finding(s):\n\n", len(findings))

	for _, f := range findings {
		status := "  "
		if hasRem[f.ID()] {
			status = "✓ "
		}

		fmt.Printf("%s%s [%s] %s\n",
			status,
			f.ID(),
			f.EffectiveSeverity(),
			f.Title(),
		)
		fmt.Printf("   %s:%d\n", f.Location().File(), f.Location().Line())
	}

	fmt.Println()
	fmt.Println("✓ = remediation cached")
	fmt.Println()
	fmt.Println("Usage: verdict fix <finding-id>")

	return nil
}

func runRollback(ctx context.Context) error {
	applier := fixer.NewApplier()

	backups, err := applier.ListBackups()
	if err != nil {
		return err
	}

	if len(backups) == 0 {
		fmt.Println("No backups found.")
		return nil
	}

	fmt.Printf("Found %d backup(s):\n", len(backups))
	for _, b := range backups {
		fmt.Printf("  - %s\n", b)
	}
	fmt.Println()

	// Confirm rollback
	if !fixNoConfirm {
		fmt.Print("Restore from latest backup? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	if err := applier.RollbackLatest(); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	fmt.Println("Rollback complete.")
	return nil
}
