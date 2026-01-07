package workspace

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// ModuleResult represents the scan result for a single module.
type ModuleResult struct {
	Module     Module
	Assessment *assessment.Assessment
	Error      error
}

// ScanFunc is a function that scans a single module.
type ScanFunc func(ctx context.Context, target ports.Target) (*assessment.Assessment, error)

// ProgressFunc is called when a module scan completes.
type ProgressFunc func(module Module, result *ModuleResult, completed, total int)

// ParallelScanner scans multiple modules concurrently.
type ParallelScanner struct {
	maxWorkers int
	progress   ProgressFunc
}

// ParallelScannerOption is a functional option for ParallelScanner.
type ParallelScannerOption func(*ParallelScanner)

// WithMaxWorkers sets the maximum number of concurrent workers.
func WithMaxWorkers(n int) ParallelScannerOption {
	return func(p *ParallelScanner) {
		if n > 0 {
			p.maxWorkers = n
		}
	}
}

// WithProgress sets a progress callback.
func WithProgress(fn ProgressFunc) ParallelScannerOption {
	return func(p *ParallelScanner) { p.progress = fn }
}

// NewParallelScanner creates a new parallel scanner.
func NewParallelScanner(opts ...ParallelScannerOption) *ParallelScanner {
	p := &ParallelScanner{
		maxWorkers: 4,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Scan scans all provided modules in parallel.
func (p *ParallelScanner) Scan(ctx context.Context, rootPath string, modules []Module, scanFn ScanFunc) ([]ModuleResult, error) {
	if len(modules) == 0 {
		return nil, nil
	}

	// Create work channel
	work := make(chan Module, len(modules))
	results := make(chan ModuleResult, len(modules))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < min(p.maxWorkers, len(modules)); i++ {
		wg.Add(1)
		go p.worker(ctx, rootPath, work, results, scanFn, &wg)
	}

	// Send work
	for _, mod := range modules {
		work <- mod
	}
	close(work)

	// Wait for completion in separate goroutine
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var moduleResults []ModuleResult
	completed := 0
	total := len(modules)

	for result := range results {
		moduleResults = append(moduleResults, result)
		completed++

		// Call progress callback
		if p.progress != nil {
			p.progress(result.Module, &result, completed, total)
		}
	}

	return moduleResults, nil
}

// worker processes modules from the work channel.
func (p *ParallelScanner) worker(ctx context.Context, rootPath string, work <-chan Module, results chan<- ModuleResult, scanFn ScanFunc, wg *sync.WaitGroup) {
	defer wg.Done()

	for mod := range work {
		select {
		case <-ctx.Done():
			results <- ModuleResult{
				Module: mod,
				Error:  ctx.Err(),
			}
			continue
		default:
		}

		// Build target path
		targetPath := filepath.Join(rootPath, mod.Path)
		target := ports.NewTarget(targetPath)

		// Run scan
		assess, err := scanFn(ctx, target)

		results <- ModuleResult{
			Module:     mod,
			Assessment: assess,
			Error:      err,
		}
	}
}

// ScanWithFilter scans modules matching a filter pattern.
func (p *ParallelScanner) ScanWithFilter(ctx context.Context, rootPath string, modules []Module, filter string, scanFn ScanFunc) ([]ModuleResult, error) {
	// Filter modules
	var filtered []Module
	for _, mod := range modules {
		matched, _ := filepath.Match(filter, mod.Path)
		if matched {
			filtered = append(filtered, mod)
		}
		// Also check if filter is a prefix
		if !matched && (filter == "" || matchPrefix(mod.Path, filter)) {
			filtered = append(filtered, mod)
		}
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("no modules match filter: %s", filter)
	}

	return p.Scan(ctx, rootPath, filtered, scanFn)
}

// matchPrefix checks if path starts with prefix pattern.
func matchPrefix(path, prefix string) bool {
	// Remove trailing wildcards
	prefix = filepath.Clean(prefix)
	if len(prefix) > 0 && prefix[len(prefix)-1] == '*' {
		prefix = prefix[:len(prefix)-1]
	}

	// Check prefix match
	return len(path) >= len(prefix) && path[:len(prefix)] == prefix
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AggregatedResult combines results from multiple modules.
type AggregatedResult struct {
	// Modules contains individual module results.
	Modules []ModuleResult

	// TotalFindings is the total count of findings across all modules.
	TotalFindings int

	// FindingsByModule maps module path to finding count.
	FindingsByModule map[string]int

	// FindingsBySeverity maps severity to count.
	FindingsBySeverity map[finding.Severity]int

	// FailedModules contains modules that failed to scan.
	FailedModules []Module

	// SuccessfulModules contains modules that scanned successfully.
	SuccessfulModules []Module
}

// Aggregate combines multiple module results into an aggregated result.
func Aggregate(results []ModuleResult) *AggregatedResult {
	agg := &AggregatedResult{
		Modules:            results,
		FindingsByModule:   make(map[string]int),
		FindingsBySeverity: make(map[finding.Severity]int),
	}

	for _, r := range results {
		if r.Error != nil {
			agg.FailedModules = append(agg.FailedModules, r.Module)
			continue
		}

		agg.SuccessfulModules = append(agg.SuccessfulModules, r.Module)

		if r.Assessment == nil {
			continue
		}

		findings := r.Assessment.Findings()
		count := len(findings)
		agg.TotalFindings += count
		agg.FindingsByModule[r.Module.Path] = count

		for _, f := range findings {
			sev := f.EffectiveSeverity()
			agg.FindingsBySeverity[sev]++
		}
	}

	return agg
}

// AllFindings returns all findings from all modules.
func (a *AggregatedResult) AllFindings() []*finding.Finding {
	var all []*finding.Finding
	for _, r := range a.Modules {
		if r.Assessment != nil {
			all = append(all, r.Assessment.Findings()...)
		}
	}
	return all
}

// FindingsForModule returns findings for a specific module.
func (a *AggregatedResult) FindingsForModule(modulePath string) []*finding.Finding {
	for _, r := range a.Modules {
		if r.Module.Path == modulePath && r.Assessment != nil {
			return r.Assessment.Findings()
		}
	}
	return nil
}

// HasErrors returns true if any module failed to scan.
func (a *AggregatedResult) HasErrors() bool {
	return len(a.FailedModules) > 0
}

// Summary returns a human-readable summary.
func (a *AggregatedResult) Summary() string {
	return fmt.Sprintf(
		"Scanned %d modules (%d successful, %d failed), found %d findings",
		len(a.Modules),
		len(a.SuccessfulModules),
		len(a.FailedModules),
		a.TotalFindings,
	)
}
