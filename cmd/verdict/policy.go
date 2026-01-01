package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// policyCmd is the parent command for policy operations
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage security policies",
	Long: `Manage and validate security policies.

Policies define thresholds and suppressions for security findings.

Examples:
  verdict policy lint              # Validate policy configuration`,
}

// policyLintCmd validates policy configuration
var policyLintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Validate policy configuration",
	Long: `Validate the current policy configuration for errors.

Checks:
  - Valid severity thresholds
  - Valid baseline mode
  - Valid suppression entries (fingerprint, reason, owner)
  - No expired suppressions (warning only)

Examples:
  verdict policy lint              # Lint default config
  verdict policy lint -c custom.yaml   # Lint specific config`,
	RunE: runPolicyLint,
}

func init() {
	policyCmd.AddCommand(policyLintCmd)
	rootCmd.AddCommand(policyCmd)
}

func runPolicyLint(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Validate configuration
	errors := cfg.Validate()

	// Check for expired suppressions (warning)
	policy := cfg.ToDomainPolicy()
	expiredSuppressions := policy.ExpiredSuppressions()

	// Print results
	success := color.New(color.FgGreen)
	warning := color.New(color.FgYellow)
	errorColor := color.New(color.FgRed)

	if len(errors) == 0 && len(expiredSuppressions) == 0 {
		_, _ = success.Println("✓ Policy configuration is valid")
		return nil
	}

	if len(errors) > 0 {
		_, _ = errorColor.Printf("✗ Found %d error(s) in policy configuration:\n", len(errors))
		for _, e := range errors {
			_, _ = errorColor.Printf("  • %s\n", e.Error())
		}
	}

	if len(expiredSuppressions) > 0 {
		_, _ = warning.Printf("⚠ Found %d expired suppression(s):\n", len(expiredSuppressions))
		for _, s := range expiredSuppressions {
			_, _ = warning.Printf("  • %s (expired: %s, owner: %s)\n",
				s.Fingerprint[:min(12, len(s.Fingerprint))]+"...",
				s.ExpiresAt.Format("2006-01-02"),
				s.Owner)
		}
		_, _ = fmt.Println("\nConsider cleaning up expired suppressions with:")
		_, _ = fmt.Println("  verdict policy cleanup")
	}

	if len(errors) > 0 {
		return fmt.Errorf("policy validation failed with %d error(s)", len(errors))
	}

	return nil
}
