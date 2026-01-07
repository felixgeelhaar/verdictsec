package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParseRefRange(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RefRange
		wantErr bool
	}{
		{
			name:  "simple branch range",
			input: "main..feature",
			want:  RefRange{From: "main", To: "feature"},
		},
		{
			name:  "tag range",
			input: "v1.0.0..v1.1.0",
			want:  RefRange{From: "v1.0.0", To: "v1.1.0"},
		},
		{
			name:  "commit range with HEAD",
			input: "HEAD~5..HEAD",
			want:  RefRange{From: "HEAD~5", To: "HEAD"},
		},
		{
			name:  "to defaults to HEAD when empty",
			input: "main..",
			want:  RefRange{From: "main", To: "HEAD"},
		},
		{
			name:  "with whitespace",
			input: " main .. feature ",
			want:  RefRange{From: "main", To: "feature"},
		},
		{
			name:    "missing separator",
			input:   "main",
			wantErr: true,
		},
		{
			name:    "empty from ref",
			input:   "..feature",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "triple dot (not supported)",
			input:   "main...feature",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRefRange(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRefRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.From != tt.want.From {
					t.Errorf("ParseRefRange().From = %v, want %v", got.From, tt.want.From)
				}
				if got.To != tt.want.To {
					t.Errorf("ParseRefRange().To = %v, want %v", got.To, tt.want.To)
				}
			}
		})
	}
}

func TestCheckoutHelper(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// Create a temporary git repository for testing
	tempDir, err := os.MkdirTemp("", "git-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize git repo
	mustRun(t, tempDir, "git", "init")
	mustRun(t, tempDir, "git", "config", "user.email", "test@test.com")
	mustRun(t, tempDir, "git", "config", "user.name", "Test User")

	// Create initial commit
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("initial content"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	mustRun(t, tempDir, "git", "add", ".")
	mustRun(t, tempDir, "git", "commit", "-m", "initial commit")

	// Create a lightweight tag
	mustRun(t, tempDir, "git", "tag", "-a", "v1.0.0", "-m", "Release v1.0.0")

	// Create second commit
	if err := os.WriteFile(testFile, []byte("updated content"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	mustRun(t, tempDir, "git", "add", ".")
	mustRun(t, tempDir, "git", "commit", "-m", "second commit")

	helper := NewCheckoutHelper(tempDir)
	defer helper.Cleanup()

	t.Run("ValidateRef valid ref", func(t *testing.T) {
		err := helper.ValidateRef("v1.0.0")
		if err != nil {
			t.Errorf("ValidateRef() error = %v, want nil", err)
		}
	})

	t.Run("ValidateRef invalid ref", func(t *testing.T) {
		err := helper.ValidateRef("nonexistent-tag")
		if err == nil {
			t.Error("ValidateRef() expected error for invalid ref")
		}
	})

	t.Run("ResolveRef", func(t *testing.T) {
		sha, err := helper.ResolveRef("v1.0.0")
		if err != nil {
			t.Errorf("ResolveRef() error = %v", err)
		}
		if len(sha) != 40 {
			t.Errorf("ResolveRef() returned invalid SHA: %v", sha)
		}
	})

	t.Run("GetCurrentBranch", func(t *testing.T) {
		branch, err := helper.GetCurrentBranch()
		if err != nil {
			t.Errorf("GetCurrentBranch() error = %v", err)
		}
		// Should be master or main depending on git version
		if branch != "master" && branch != "main" {
			t.Errorf("GetCurrentBranch() = %v, want master or main", branch)
		}
	})

	t.Run("IsWorkingTreeClean clean", func(t *testing.T) {
		clean, err := helper.IsWorkingTreeClean()
		if err != nil {
			t.Errorf("IsWorkingTreeClean() error = %v", err)
		}
		if !clean {
			t.Error("IsWorkingTreeClean() = false, want true")
		}
	})

	t.Run("IsWorkingTreeClean dirty", func(t *testing.T) {
		// Make a change
		if err := os.WriteFile(testFile, []byte("dirty content"), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
		defer func() {
			// Reset the change
			mustRun(t, tempDir, "git", "checkout", "--", "test.txt")
		}()

		clean, err := helper.IsWorkingTreeClean()
		if err != nil {
			t.Errorf("IsWorkingTreeClean() error = %v", err)
		}
		if clean {
			t.Error("IsWorkingTreeClean() = true, want false")
		}
	})

	t.Run("CheckoutToTemp", func(t *testing.T) {
		checkoutDir, err := helper.CheckoutToTemp("v1.0.0")
		if err != nil {
			t.Fatalf("CheckoutToTemp() error = %v", err)
		}

		// Verify the file has the old content
		content, err := os.ReadFile(filepath.Join(checkoutDir, "test.txt"))
		if err != nil {
			t.Fatalf("failed to read test file: %v", err)
		}
		if string(content) != "initial content" {
			t.Errorf("CheckoutToTemp() file content = %q, want %q", string(content), "initial content")
		}
	})

	t.Run("Cleanup removes temp dirs", func(t *testing.T) {
		// helper should have one temp dir from previous test
		if len(helper.tempDirs) == 0 {
			t.Skip("no temp dirs to clean")
		}

		firstTempDir := helper.tempDirs[0]

		err := helper.Cleanup()
		if err != nil {
			t.Errorf("Cleanup() error = %v", err)
		}

		if _, err := os.Stat(firstTempDir); !os.IsNotExist(err) {
			t.Error("Cleanup() did not remove temp directory")
		}

		if len(helper.tempDirs) != 0 {
			t.Error("Cleanup() did not clear tempDirs slice")
		}
	})
}

func mustRun(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("command %s %v failed: %v\noutput: %s", name, args, err, output)
	}
}
