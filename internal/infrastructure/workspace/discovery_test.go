package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscovery_FindModules(t *testing.T) {
	// Create temp directory with mock monorepo structure
	tempDir := t.TempDir()

	// Create root module
	createGoMod(t, tempDir, "github.com/test/root", "1.21")

	// Create submodules
	svcA := filepath.Join(tempDir, "services", "svc-a")
	svcB := filepath.Join(tempDir, "services", "svc-b")
	pkg := filepath.Join(tempDir, "pkg", "common")

	createGoMod(t, svcA, "github.com/test/root/services/svc-a", "1.21")
	createGoMod(t, svcB, "github.com/test/root/services/svc-b", "1.22")
	createGoMod(t, pkg, "github.com/test/root/pkg/common", "1.20")

	// Create vendor directory (should be excluded)
	vendor := filepath.Join(tempDir, "vendor", "github.com", "dep")
	createGoMod(t, vendor, "github.com/dep/module", "1.21")

	discovery := NewDiscovery(tempDir, DefaultDiscoveryOptions())
	modules, err := discovery.FindModules()
	if err != nil {
		t.Fatalf("FindModules failed: %v", err)
	}

	// Should find 4 modules (root + 3 submodules), not vendor
	if len(modules) != 4 {
		t.Errorf("expected 4 modules, got %d", len(modules))
		for _, m := range modules {
			t.Logf("  found: %s (%s)", m.Path, m.Name)
		}
	}

	// Verify vendor is excluded
	for _, m := range modules {
		if m.Name == "github.com/dep/module" {
			t.Error("vendor module should be excluded")
		}
	}
}

func TestDiscovery_FindModules_Empty(t *testing.T) {
	tempDir := t.TempDir()

	discovery := NewDiscovery(tempDir, DefaultDiscoveryOptions())
	modules, err := discovery.FindModules()
	if err != nil {
		t.Fatalf("FindModules failed: %v", err)
	}

	if len(modules) != 0 {
		t.Errorf("expected 0 modules, got %d", len(modules))
	}
}

func TestDiscovery_FindModules_SingleModule(t *testing.T) {
	tempDir := t.TempDir()
	createGoMod(t, tempDir, "github.com/test/single", "1.21")

	discovery := NewDiscovery(tempDir, DefaultDiscoveryOptions())
	modules, err := discovery.FindModules()
	if err != nil {
		t.Fatalf("FindModules failed: %v", err)
	}

	if len(modules) != 1 {
		t.Errorf("expected 1 module, got %d", len(modules))
	}

	if modules[0].Name != "github.com/test/single" {
		t.Errorf("expected module name 'github.com/test/single', got %s", modules[0].Name)
	}

	if modules[0].GoVersion != "1.21" {
		t.Errorf("expected go version '1.21', got %s", modules[0].GoVersion)
	}
}

func TestDiscovery_FindModules_WithIncludePatterns(t *testing.T) {
	tempDir := t.TempDir()

	// Create modules in different directories
	svcA := filepath.Join(tempDir, "services", "svc-a")
	svcB := filepath.Join(tempDir, "services", "svc-b")
	pkg := filepath.Join(tempDir, "pkg", "common")

	createGoMod(t, svcA, "github.com/test/svc-a", "1.21")
	createGoMod(t, svcB, "github.com/test/svc-b", "1.21")
	createGoMod(t, pkg, "github.com/test/common", "1.21")

	opts := DefaultDiscoveryOptions()
	opts.IncludePatterns = []string{"services/*"}

	discovery := NewDiscovery(tempDir, opts)
	modules, err := discovery.FindModules()
	if err != nil {
		t.Fatalf("FindModules failed: %v", err)
	}

	// Should only find services modules
	if len(modules) != 2 {
		t.Errorf("expected 2 modules, got %d", len(modules))
	}

	for _, m := range modules {
		if m.Name == "github.com/test/common" {
			t.Error("pkg/common should be excluded by include pattern")
		}
	}
}

func TestDiscovery_IsMonorepo(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(dir string)
		expected bool
	}{
		{
			name:     "empty",
			setup:    func(dir string) {},
			expected: false,
		},
		{
			name: "single module",
			setup: func(dir string) {
				createGoModHelper(dir, "github.com/test/single", "1.21")
			},
			expected: false,
		},
		{
			name: "monorepo",
			setup: func(dir string) {
				createGoModHelper(dir, "github.com/test/root", "1.21")
				createGoModHelper(filepath.Join(dir, "pkg"), "github.com/test/pkg", "1.21")
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			tt.setup(tempDir)

			discovery := NewDiscovery(tempDir, DefaultDiscoveryOptions())
			isMonorepo, err := discovery.IsMonorepo()
			if err != nil {
				t.Fatalf("IsMonorepo failed: %v", err)
			}

			if isMonorepo != tt.expected {
				t.Errorf("expected IsMonorepo=%v, got %v", tt.expected, isMonorepo)
			}
		})
	}
}

func TestDiscovery_FindModule(t *testing.T) {
	tempDir := t.TempDir()

	svcA := filepath.Join(tempDir, "services", "svc-a")
	svcB := filepath.Join(tempDir, "services", "svc-b")

	createGoMod(t, svcA, "github.com/test/svc-a", "1.21")
	createGoMod(t, svcB, "github.com/test/svc-b", "1.21")

	discovery := NewDiscovery(tempDir, DefaultDiscoveryOptions())

	// Find by path
	mod, err := discovery.FindModule("services/svc-a")
	if err != nil {
		t.Fatalf("FindModule failed: %v", err)
	}
	if mod.Name != "github.com/test/svc-a" {
		t.Errorf("expected svc-a, got %s", mod.Name)
	}

	// Find by module name
	mod, err = discovery.FindModule("github.com/test/svc-b")
	if err != nil {
		t.Fatalf("FindModule failed: %v", err)
	}
	if mod.Path != "services/svc-b" {
		t.Errorf("expected services/svc-b, got %s", mod.Path)
	}

	// Not found
	_, err = discovery.FindModule("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent module")
	}
}

func TestDiscovery_MaxDepth(t *testing.T) {
	tempDir := t.TempDir()

	// Create deeply nested module
	deep := filepath.Join(tempDir, "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k")
	createGoMod(t, deep, "github.com/test/deep", "1.21")

	// Create shallow module
	shallow := filepath.Join(tempDir, "shallow")
	createGoMod(t, shallow, "github.com/test/shallow", "1.21")

	opts := DefaultDiscoveryOptions()
	opts.MaxDepth = 3

	discovery := NewDiscovery(tempDir, opts)
	modules, err := discovery.FindModules()
	if err != nil {
		t.Fatalf("FindModules failed: %v", err)
	}

	// Should only find shallow module
	if len(modules) != 1 {
		t.Errorf("expected 1 module, got %d", len(modules))
	}

	if len(modules) > 0 && modules[0].Name != "github.com/test/shallow" {
		t.Errorf("expected shallow module, got %s", modules[0].Name)
	}
}

// Helper functions

func createGoMod(t *testing.T, dir, moduleName, goVersion string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}

	content := "module " + moduleName + "\n\ngo " + goVersion + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func createGoModHelper(dir, moduleName, goVersion string) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}

	content := "module " + moduleName + "\n\ngo " + goVersion + "\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0644)
}
