package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RefRange represents a git ref range for comparison.
type RefRange struct {
	From string
	To   string
}

// ParseRefRange parses a ref range string like "main..feature" or "v1.0.0..HEAD".
// Only double-dot notation is supported (not triple-dot).
func ParseRefRange(rangeStr string) (RefRange, error) {
	// Check for triple-dot (not supported)
	if strings.Contains(rangeStr, "...") {
		return RefRange{}, fmt.Errorf("triple-dot notation not supported: %q (use double-dot 'from..to')", rangeStr)
	}

	parts := strings.Split(rangeStr, "..")
	if len(parts) != 2 {
		return RefRange{}, fmt.Errorf("invalid ref range format: %q (expected 'from..to')", rangeStr)
	}

	from := strings.TrimSpace(parts[0])
	to := strings.TrimSpace(parts[1])

	if from == "" {
		return RefRange{}, fmt.Errorf("empty 'from' ref in range: %q", rangeStr)
	}
	if to == "" {
		to = "HEAD"
	}

	return RefRange{From: from, To: to}, nil
}

// CheckoutHelper provides git checkout operations for ref comparison.
type CheckoutHelper struct {
	repoPath string
	tempDirs []string
}

// NewCheckoutHelper creates a new checkout helper for the given repository.
func NewCheckoutHelper(repoPath string) *CheckoutHelper {
	return &CheckoutHelper{
		repoPath: repoPath,
		tempDirs: []string{},
	}
}

// CheckoutToTemp checks out a ref to a temporary directory.
// Returns the path to the temporary directory.
func (h *CheckoutHelper) CheckoutToTemp(ref string) (string, error) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "verdict-diff-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	h.tempDirs = append(h.tempDirs, tempDir)

	// Get the absolute path to the repo
	absRepoPath, err := filepath.Abs(h.repoPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute repo path: %w", err)
	}

	// Clone the repository to temp with --no-checkout
	// #nosec G204 -- absRepoPath is validated via filepath.Abs, tempDir is from os.MkdirTemp
	cloneCmd := exec.Command("git", "clone", "--no-checkout", "--shared", absRepoPath, tempDir)
	cloneCmd.Dir = h.repoPath
	if output, err := cloneCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to clone repository: %w\noutput: %s", err, output)
	}

	// Checkout the specific ref
	checkoutCmd := exec.Command("git", "checkout", ref)
	checkoutCmd.Dir = tempDir
	if output, err := checkoutCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to checkout ref %q: %w\noutput: %s", ref, err, output)
	}

	return tempDir, nil
}

// Cleanup removes all temporary directories created by this helper.
func (h *CheckoutHelper) Cleanup() error {
	var errs []error
	for _, dir := range h.tempDirs {
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove %s: %w", dir, err))
		}
	}
	h.tempDirs = nil

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}
	return nil
}

// ResolveRef resolves a ref to its commit SHA.
func (h *CheckoutHelper) ResolveRef(ref string) (string, error) {
	cmd := exec.Command("git", "rev-parse", ref)
	cmd.Dir = h.repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to resolve ref %q: %w", ref, err)
	}
	return strings.TrimSpace(string(output)), nil
}

// ValidateRef checks if a ref exists in the repository.
func (h *CheckoutHelper) ValidateRef(ref string) error {
	cmd := exec.Command("git", "rev-parse", "--verify", ref)
	cmd.Dir = h.repoPath
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("invalid ref %q: %w\noutput: %s", ref, err, output)
	}
	return nil
}

// GetCurrentBranch returns the current branch name or "HEAD" if detached.
func (h *CheckoutHelper) GetCurrentBranch() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = h.repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get current branch: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// IsWorkingTreeClean checks if there are uncommitted changes.
func (h *CheckoutHelper) IsWorkingTreeClean() (bool, error) {
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = h.repoPath
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("failed to check working tree status: %w", err)
	}
	return len(strings.TrimSpace(string(output))) == 0, nil
}

// GetRepoRoot returns the root directory of the git repository.
func (h *CheckoutHelper) GetRepoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = h.repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get repo root: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}
