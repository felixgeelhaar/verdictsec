package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	hookForce   bool
	hookEngines []string
	hookStrict  bool
)

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Manage git hooks for VerdictSec",
	Long: `Manage git hooks to integrate VerdictSec into your development workflow.

Use 'verdict hook install' to set up a pre-commit hook that runs
security scans before each commit.`,
}

var hookInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install a pre-commit hook",
	Long: `Install a git pre-commit hook that runs VerdictSec before each commit.

The hook will:
  - Run gosec (SAST) and gitleaks (secrets) scans
  - Block commits if critical or high severity findings are detected
  - Show a summary of findings

Examples:
  verdict hook install                    # Install with defaults
  verdict hook install --force            # Overwrite existing hook
  verdict hook install --engines=gosec    # Only run specific engines
  verdict hook install --strict           # Also fail on warnings`,
	RunE: runHookInstall,
}

var hookUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the pre-commit hook",
	Long:  `Remove the VerdictSec pre-commit hook from the repository.`,
	RunE:  runHookUninstall,
}

var hookStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check pre-commit hook status",
	Long:  `Check if a VerdictSec pre-commit hook is installed.`,
	RunE:  runHookStatus,
}

func init() {
	hookInstallCmd.Flags().BoolVarP(&hookForce, "force", "f", false, "overwrite existing pre-commit hook")
	hookInstallCmd.Flags().StringSliceVar(&hookEngines, "engines", []string{"gosec", "gitleaks"}, "engines to run in hook")
	hookInstallCmd.Flags().BoolVar(&hookStrict, "strict", false, "fail on warnings (not just errors)")

	hookCmd.AddCommand(hookInstallCmd)
	hookCmd.AddCommand(hookUninstallCmd)
	hookCmd.AddCommand(hookStatusCmd)

	rootCmd.AddCommand(hookCmd)
}

const hookMarker = "# VerdictSec pre-commit hook"

func runHookInstall(cmd *cobra.Command, args []string) error {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	if noColor {
		green = fmt.Sprint
		yellow = fmt.Sprint
		red = fmt.Sprint
	}

	// Find .git directory
	gitDir, err := findGitDir()
	if err != nil {
		return fmt.Errorf("%s Not a git repository", red("\u2717"))
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")

	// Check if hook already exists
	if _, err := os.Stat(hookPath); err == nil {
		// #nosec G304 -- hookPath is constructed from git directory, not user input
		content, _ := os.ReadFile(hookPath)
		if !hookForce {
			if containsMarker(string(content)) {
				fmt.Printf("%s VerdictSec hook already installed at %s\n", yellow("!"), hookPath)
				fmt.Println("  Use --force to reinstall")
				return nil
			}
			return fmt.Errorf("%s Pre-commit hook already exists\n  Use --force to overwrite", red("\u2717"))
		}
		fmt.Printf("%s Overwriting existing pre-commit hook\n", yellow("!"))
	}

	// Ensure hooks directory exists
	hooksDir := filepath.Dir(hookPath)
	// #nosec G301 -- 0755 is standard for git hooks directory (needs to be executable)
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	// Generate hook script
	hookScript := generateHookScript()

	// Write hook file
	// #nosec G306 -- 0755 is required for executable git hook scripts
	if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
		return fmt.Errorf("failed to write hook: %w", err)
	}

	fmt.Printf("%s Pre-commit hook installed at %s\n", green("\u2713"), hookPath)
	fmt.Println("\nThe hook will run the following checks before each commit:")
	for _, engine := range hookEngines {
		fmt.Printf("  - %s\n", engine)
	}

	if hookStrict {
		fmt.Println("\nStrict mode: Will fail on warnings")
	} else {
		fmt.Println("\nWill fail on HIGH or CRITICAL severity findings")
	}

	fmt.Println("\nTo skip the hook temporarily, use: git commit --no-verify")

	return nil
}

func runHookUninstall(cmd *cobra.Command, args []string) error {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	if noColor {
		green = fmt.Sprint
		yellow = fmt.Sprint
		red = fmt.Sprint
	}

	gitDir, err := findGitDir()
	if err != nil {
		return fmt.Errorf("%s Not a git repository", red("\u2717"))
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")

	// #nosec G304 -- hookPath is constructed from git directory, not user input
	content, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("%s No pre-commit hook installed\n", yellow("!"))
			return nil
		}
		return fmt.Errorf("failed to read hook: %w", err)
	}

	if !containsMarker(string(content)) {
		return fmt.Errorf("%s Pre-commit hook exists but is not a VerdictSec hook\n  Remove manually if desired", yellow("!"))
	}

	if err := os.Remove(hookPath); err != nil {
		return fmt.Errorf("failed to remove hook: %w", err)
	}

	fmt.Printf("%s Pre-commit hook uninstalled\n", green("\u2713"))
	return nil
}

func runHookStatus(cmd *cobra.Command, args []string) error {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	if noColor {
		green = fmt.Sprint
		yellow = fmt.Sprint
		red = fmt.Sprint
	}

	gitDir, err := findGitDir()
	if err != nil {
		return fmt.Errorf("%s Not a git repository", red("\u2717"))
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")

	// #nosec G304 -- hookPath is constructed from git directory, not user input
	content, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("%s No pre-commit hook installed\n", yellow("!"))
			fmt.Println("  Run 'verdict hook install' to set up")
			return nil
		}
		return fmt.Errorf("failed to read hook: %w", err)
	}

	if containsMarker(string(content)) {
		fmt.Printf("%s VerdictSec pre-commit hook is installed\n", green("\u2713"))
		fmt.Printf("  Location: %s\n", hookPath)
	} else {
		fmt.Printf("%s Pre-commit hook exists but is not a VerdictSec hook\n", yellow("!"))
	}

	return nil
}

func findGitDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		gitPath := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
			return gitPath, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("not a git repository")
		}
		dir = parent
	}
}

func containsMarker(content string) bool {
	return len(content) >= len(hookMarker) && content[:len(hookMarker)] == hookMarker
}

func generateHookScript() string {
	enginesArg := ""
	if len(hookEngines) > 0 {
		enginesArg = " --include=" + hookEngines[0]
		for _, e := range hookEngines[1:] {
			enginesArg += "," + e
		}
	}

	strictArg := ""
	if hookStrict {
		strictArg = " --strict"
	}

	return fmt.Sprintf(`%s
# Runs security scans before allowing commits
# To skip: git commit --no-verify
# To uninstall: verdict hook uninstall

set -e

echo "Running VerdictSec security scan..."

# Run verdict scan on staged files
verdict scan%s%s --summary

exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo ""
    echo "Security issues detected. Commit blocked."
    echo "Fix the issues or use 'git commit --no-verify' to skip."
    exit 1
fi

echo "Security scan passed."
exit 0
`, hookMarker, enginesArg, strictArg)
}
