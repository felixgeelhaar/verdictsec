package fixer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/advisory"
)

// ApplyResult represents the result of applying a fix.
type ApplyResult struct {
	FilePath   string
	Applied    bool
	Diff       string
	Error      error
	BackupPath string
}

// Applier applies code suggestions to files.
type Applier struct {
	dryRun    bool
	backupDir string
	baseDir   string
}

// ApplierOption is a functional option for the Applier.
type ApplierOption func(*Applier)

// WithDryRun sets the applier to preview mode without making changes.
func WithDryRun(dryRun bool) ApplierOption {
	return func(a *Applier) { a.dryRun = dryRun }
}

// WithBackupDir sets a custom backup directory.
func WithBackupDir(dir string) ApplierOption {
	return func(a *Applier) { a.backupDir = dir }
}

// WithBaseDir sets the base directory for relative file paths.
func WithBaseDir(dir string) ApplierOption {
	return func(a *Applier) { a.baseDir = dir }
}

// NewApplier creates a new applier with options.
func NewApplier(opts ...ApplierOption) *Applier {
	a := &Applier{
		backupDir: BackupDir,
		baseDir:   ".",
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// Apply applies a single code suggestion to a file.
func (a *Applier) Apply(suggestion advisory.CodeSuggestion) (*ApplyResult, error) {
	result := &ApplyResult{
		FilePath: suggestion.FilePath,
	}

	// Resolve file path
	filePath := suggestion.FilePath
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(a.baseDir, filePath)
	}

	// Read the original file
	content, err := os.ReadFile(filePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to read file: %w", err)
		return result, result.Error
	}

	// Generate the modified content
	lines := strings.Split(string(content), "\n")
	modified, err := a.applyToLines(lines, suggestion)
	if err != nil {
		result.Error = err
		return result, err
	}

	// Generate diff for preview
	result.Diff = a.generateDiff(string(content), modified, suggestion.FilePath)

	// If dry run, stop here
	if a.dryRun {
		result.Applied = false
		return result, nil
	}

	// Create backup
	backupPath, err := a.createBackup(filePath, content)
	if err != nil {
		result.Error = fmt.Errorf("failed to create backup: %w", err)
		return result, result.Error
	}
	result.BackupPath = backupPath

	// Write modified content
	if err := os.WriteFile(filePath, []byte(modified), 0644); err != nil {
		result.Error = fmt.Errorf("failed to write file: %w", err)
		return result, result.Error
	}

	// Run gofmt if it's a Go file
	if strings.HasSuffix(filePath, ".go") {
		if err := a.runGoFmt(filePath); err != nil {
			// Non-fatal, just log
			fmt.Fprintf(os.Stderr, "Warning: gofmt failed: %v\n", err)
		}
	}

	result.Applied = true
	return result, nil
}

// ApplyAll applies multiple code suggestions.
func (a *Applier) ApplyAll(suggestions []advisory.CodeSuggestion) ([]*ApplyResult, error) {
	results := make([]*ApplyResult, 0, len(suggestions))

	for _, suggestion := range suggestions {
		result, _ := a.Apply(suggestion)
		results = append(results, result)
	}

	return results, nil
}

// applyToLines applies a suggestion to the file lines.
func (a *Applier) applyToLines(lines []string, suggestion advisory.CodeSuggestion) (string, error) {
	// If we have specific line numbers, replace those lines
	if suggestion.LineStart > 0 && suggestion.LineEnd > 0 {
		if suggestion.LineStart > len(lines) || suggestion.LineEnd > len(lines) {
			return "", fmt.Errorf("line numbers out of range: %d-%d (file has %d lines)",
				suggestion.LineStart, suggestion.LineEnd, len(lines))
		}

		// Convert to 0-indexed
		start := suggestion.LineStart - 1
		end := suggestion.LineEnd

		// Build new content
		var result []string
		result = append(result, lines[:start]...)
		result = append(result, strings.Split(suggestion.Replacement, "\n")...)
		if end < len(lines) {
			result = append(result, lines[end:]...)
		}

		return strings.Join(result, "\n"), nil
	}

	// If we have original content, do string replacement
	if suggestion.Original != "" {
		content := strings.Join(lines, "\n")
		if !strings.Contains(content, suggestion.Original) {
			return "", fmt.Errorf("original content not found in file")
		}

		modified := strings.Replace(content, suggestion.Original, suggestion.Replacement, 1)
		return modified, nil
	}

	return "", fmt.Errorf("insufficient information to apply fix: need either line numbers or original content")
}

// generateDiff creates a unified diff between original and modified content.
func (a *Applier) generateDiff(original, modified, filename string) string {
	originalLines := strings.Split(original, "\n")
	modifiedLines := strings.Split(modified, "\n")

	var diff strings.Builder
	diff.WriteString(fmt.Sprintf("--- a/%s\n", filename))
	diff.WriteString(fmt.Sprintf("+++ b/%s\n", filename))

	// Simple diff - show removed and added lines
	// For a real implementation, use a proper diff algorithm
	diff.WriteString("@@ -1 +1 @@\n")

	for _, line := range originalLines {
		if !contains(modifiedLines, line) {
			diff.WriteString(fmt.Sprintf("-%s\n", line))
		}
	}

	for _, line := range modifiedLines {
		if !contains(originalLines, line) {
			diff.WriteString(fmt.Sprintf("+%s\n", line))
		}
	}

	return diff.String()
}

// createBackup creates a backup of the original file.
func (a *Applier) createBackup(filePath string, content []byte) (string, error) {
	// Create timestamped backup directory
	timestamp := time.Now().Format("20060102-150405")
	backupDir := filepath.Join(a.backupDir, timestamp)

	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return "", err
	}

	// Use relative path for backup filename
	relPath := filePath
	if filepath.IsAbs(filePath) {
		var err error
		relPath, err = filepath.Rel(a.baseDir, filePath)
		if err != nil {
			relPath = filepath.Base(filePath)
		}
	}

	// Flatten path for backup filename
	backupName := strings.ReplaceAll(relPath, string(filepath.Separator), "_")
	backupPath := filepath.Join(backupDir, backupName)

	if err := os.WriteFile(backupPath, content, 0600); err != nil {
		return "", err
	}

	return backupPath, nil
}

// runGoFmt runs gofmt on a Go file.
func (a *Applier) runGoFmt(filePath string) error {
	cmd := exec.Command("gofmt", "-w", filePath)
	return cmd.Run()
}

// Rollback restores a file from backup.
func (a *Applier) Rollback(backupPath, targetPath string) error {
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	if err := os.WriteFile(targetPath, content, 0644); err != nil {
		return fmt.Errorf("failed to restore file: %w", err)
	}

	return nil
}

// ListBackups lists available backup sets.
func (a *Applier) ListBackups() ([]string, error) {
	entries, err := os.ReadDir(a.backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var backups []string
	for _, entry := range entries {
		if entry.IsDir() {
			backups = append(backups, entry.Name())
		}
	}

	return backups, nil
}

// GetLatestBackup returns the most recent backup directory.
func (a *Applier) GetLatestBackup() (string, error) {
	backups, err := a.ListBackups()
	if err != nil {
		return "", err
	}

	if len(backups) == 0 {
		return "", fmt.Errorf("no backups found")
	}

	// Backups are timestamped, so the last one is the latest
	return filepath.Join(a.backupDir, backups[len(backups)-1]), nil
}

// RollbackLatest restores files from the latest backup.
func (a *Applier) RollbackLatest() error {
	latestDir, err := a.GetLatestBackup()
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(latestDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		backupPath := filepath.Join(latestDir, entry.Name())
		// Convert flattened name back to path
		targetPath := strings.ReplaceAll(entry.Name(), "_", string(filepath.Separator))

		if err := a.Rollback(backupPath, targetPath); err != nil {
			return fmt.Errorf("failed to rollback %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// contains checks if a slice contains a string.
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// CheckGitStatus checks if there are uncommitted changes.
func CheckGitStatus() (bool, error) {
	cmd := exec.Command("git", "status", "--porcelain")
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}

	return len(strings.TrimSpace(string(output))) > 0, nil
}
