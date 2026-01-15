// Package workspace provides monorepo support for scanning multiple Go modules.
package workspace

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Module represents a discovered Go module in the workspace.
type Module struct {
	// Path is the relative path to the module directory.
	Path string

	// Name is the module name from go.mod.
	Name string

	// GoVersion is the Go version specified in go.mod.
	GoVersion string
}

// DiscoveryOptions configures module discovery.
type DiscoveryOptions struct {
	// ExcludePatterns are glob patterns to exclude from discovery.
	ExcludePatterns []string

	// IncludePatterns are glob patterns to include (if empty, include all).
	IncludePatterns []string

	// MaxDepth limits the directory search depth (0 = unlimited).
	MaxDepth int

	// FollowSymlinks enables following symbolic links.
	FollowSymlinks bool
}

// DefaultDiscoveryOptions returns sensible defaults.
func DefaultDiscoveryOptions() DiscoveryOptions {
	return DiscoveryOptions{
		ExcludePatterns: []string{
			"vendor/**",
			"**/vendor/**",
			".git/**",
			"**/testdata/**",
			"**/_*/**",
		},
		MaxDepth: 10,
	}
}

// Discovery finds Go modules in a workspace.
type Discovery struct {
	rootPath string
	opts     DiscoveryOptions
}

// NewDiscovery creates a new module discovery.
func NewDiscovery(rootPath string, opts DiscoveryOptions) *Discovery {
	return &Discovery{
		rootPath: rootPath,
		opts:     opts,
	}
}

// FindModules discovers all Go modules in the workspace.
func (d *Discovery) FindModules() ([]Module, error) {
	var modules []Module

	err := filepath.WalkDir(d.rootPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip if not a directory
		if !entry.IsDir() {
			// Check if this is a go.mod file
			if entry.Name() == "go.mod" {
				dir := filepath.Dir(path)
				relPath, _ := filepath.Rel(d.rootPath, dir)
				if relPath == "" {
					relPath = "."
				}

				// Check exclusions
				if d.shouldExclude(relPath) {
					return nil
				}

				// Check inclusions
				if !d.shouldInclude(relPath) {
					return nil
				}

				// Parse go.mod for module name
				mod, err := d.parseGoMod(path)
				if err != nil {
					return nil // Skip modules we can't parse
				}
				mod.Path = relPath
				modules = append(modules, mod)
			}
			return nil
		}

		// Check directory depth
		if d.opts.MaxDepth > 0 {
			relPath, _ := filepath.Rel(d.rootPath, path)
			depth := strings.Count(relPath, string(filepath.Separator))
			if depth > d.opts.MaxDepth {
				return filepath.SkipDir
			}
		}

		// Skip excluded directories
		relPath, _ := filepath.Rel(d.rootPath, path)
		if d.shouldExclude(relPath) {
			return filepath.SkipDir
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to discover modules: %w", err)
	}

	return modules, nil
}

// shouldExclude checks if a path matches any exclusion pattern.
func (d *Discovery) shouldExclude(relPath string) bool {
	for _, pattern := range d.opts.ExcludePatterns {
		matched, _ := filepath.Match(pattern, relPath)
		if matched {
			return true
		}

		// Check if path starts with pattern (for ** patterns)
		if strings.HasPrefix(pattern, "**/") {
			subPattern := strings.TrimPrefix(pattern, "**/")
			if strings.Contains(relPath, subPattern) {
				return true
			}
		}
	}
	return false
}

// shouldInclude checks if a path matches inclusion patterns (if any).
func (d *Discovery) shouldInclude(relPath string) bool {
	// If no include patterns, include everything
	if len(d.opts.IncludePatterns) == 0 {
		return true
	}

	for _, pattern := range d.opts.IncludePatterns {
		matched, _ := filepath.Match(pattern, relPath)
		if matched {
			return true
		}

		// Check prefix match for wildcard patterns
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(relPath, prefix) {
				return true
			}
		}
	}
	return false
}

// parseGoMod extracts module info from a go.mod file.
func (d *Discovery) parseGoMod(path string) (Module, error) {
	// #nosec G304 -- path is from filepath.Walk within baseDir, not user input
	file, err := os.Open(path)
	if err != nil {
		return Module{}, err
	}
	defer file.Close()

	var mod Module
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Parse module directive
		if strings.HasPrefix(line, "module ") {
			mod.Name = strings.TrimPrefix(line, "module ")
			mod.Name = strings.Trim(mod.Name, "\"")
		}

		// Parse go directive
		if strings.HasPrefix(line, "go ") {
			mod.GoVersion = strings.TrimPrefix(line, "go ")
		}

		// Early exit if we have both
		if mod.Name != "" && mod.GoVersion != "" {
			break
		}
	}

	if mod.Name == "" {
		return Module{}, fmt.Errorf("no module directive found")
	}

	return mod, nil
}

// FindModule finds a specific module by path pattern.
func (d *Discovery) FindModule(pattern string) (*Module, error) {
	modules, err := d.FindModules()
	if err != nil {
		return nil, err
	}

	for _, mod := range modules {
		matched, _ := filepath.Match(pattern, mod.Path)
		if matched || mod.Path == pattern || mod.Name == pattern {
			return &mod, nil
		}
	}

	return nil, fmt.Errorf("module not found: %s", pattern)
}

// IsMonorepo checks if the workspace contains multiple Go modules.
func (d *Discovery) IsMonorepo() (bool, error) {
	modules, err := d.FindModules()
	if err != nil {
		return false, err
	}
	return len(modules) > 1, nil
}

// ModuleCount returns the number of discovered modules.
func (d *Discovery) ModuleCount() (int, error) {
	modules, err := d.FindModules()
	if err != nil {
		return 0, err
	}
	return len(modules), nil
}
