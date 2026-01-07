package fixer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/advisory"
)

// containsStr checks if str contains substr.
func containsStr(str, substr string) bool {
	return strings.Contains(str, substr)
}

func TestApplier_Apply_WithLineNumbers(t *testing.T) {
	// Create temp directory
	tempDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tempDir, "test.go")
	content := `package main

func main() {
	secret := "hardcoded-secret"
	println(secret)
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Create suggestion
	suggestion := advisory.CodeSuggestion{
		Description: "Remove hardcoded secret",
		FilePath:    testFile,
		LineStart:   4,
		LineEnd:     4,
		Replacement: `	secret := os.Getenv("SECRET")`,
	}

	// Apply in dry-run mode first
	applier := NewApplier(WithDryRun(true))
	result, err := applier.Apply(suggestion)
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}

	if result.Applied {
		t.Error("expected Applied=false in dry run")
	}

	if result.Diff == "" {
		t.Error("expected diff to be generated")
	}

	// Verify file unchanged
	after, _ := os.ReadFile(testFile)
	if string(after) != content {
		t.Error("file was modified during dry run")
	}

	// Now apply for real
	applier = NewApplier(WithBackupDir(filepath.Join(tempDir, "backups")))
	result, err = applier.Apply(suggestion)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if !result.Applied {
		t.Error("expected Applied=true")
	}

	if result.BackupPath == "" {
		t.Error("expected backup to be created")
	}

	// Verify file changed
	after, _ = os.ReadFile(testFile)
	if !containsStr(string(after), `os.Getenv("SECRET")`) {
		t.Errorf("file was not modified correctly, got: %s", string(after))
	}
}

func TestApplier_Apply_WithOriginalContent(t *testing.T) {
	tempDir := t.TempDir()

	testFile := filepath.Join(tempDir, "test.go")
	content := `package main

var password = "admin123"
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	suggestion := advisory.CodeSuggestion{
		Description: "Use environment variable",
		FilePath:    testFile,
		Original:    `var password = "admin123"`,
		Replacement: `var password = os.Getenv("PASSWORD")`,
	}

	applier := NewApplier(WithBackupDir(filepath.Join(tempDir, "backups")))
	result, err := applier.Apply(suggestion)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if !result.Applied {
		t.Error("expected Applied=true")
	}

	after, _ := os.ReadFile(testFile)
	if !containsStr(string(after), `os.Getenv("PASSWORD")`) {
		t.Errorf("file was not modified correctly, got: %s", string(after))
	}
}

func TestApplier_Rollback(t *testing.T) {
	tempDir := t.TempDir()
	backupDir := filepath.Join(tempDir, "backups")

	testFile := filepath.Join(tempDir, "test.go")
	original := `package main

var secret = "original"
`
	if err := os.WriteFile(testFile, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	// Apply a change
	suggestion := advisory.CodeSuggestion{
		FilePath:    testFile,
		Original:    `var secret = "original"`,
		Replacement: `var secret = "modified"`,
	}

	applier := NewApplier(
		WithBackupDir(backupDir),
		WithBaseDir(tempDir),
	)
	result, err := applier.Apply(suggestion)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Verify modification
	after, _ := os.ReadFile(testFile)
	if !containsStr(string(after), `"modified"`) {
		t.Errorf("file was not modified, got: %s", string(after))
	}

	// Rollback
	if err := applier.Rollback(result.BackupPath, testFile); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	// Verify rollback
	restored, _ := os.ReadFile(testFile)
	if string(restored) != original {
		t.Error("file was not restored correctly")
	}
}

func TestApplier_ListBackups(t *testing.T) {
	tempDir := t.TempDir()
	backupDir := filepath.Join(tempDir, "backups")

	applier := NewApplier(WithBackupDir(backupDir))

	// No backups initially
	backups, err := applier.ListBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Errorf("expected 0 backups, got %d", len(backups))
	}

	// Create a test file and apply changes
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}

	suggestion := advisory.CodeSuggestion{
		FilePath:    testFile,
		Original:    "original",
		Replacement: "modified",
	}

	if _, err := applier.Apply(suggestion); err != nil {
		t.Fatal(err)
	}

	// Now should have 1 backup
	backups, err = applier.ListBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Errorf("expected 1 backup, got %d", len(backups))
	}
}
