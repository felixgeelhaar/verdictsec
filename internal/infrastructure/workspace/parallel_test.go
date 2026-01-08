package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

func TestParallelScanner_Scan(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock modules
	modules := []Module{
		{Path: "svc-a", Name: "github.com/test/svc-a"},
		{Path: "svc-b", Name: "github.com/test/svc-b"},
		{Path: "svc-c", Name: "github.com/test/svc-c"},
	}

	// Create module directories
	for _, mod := range modules {
		modPath := filepath.Join(tempDir, mod.Path)
		if err := os.MkdirAll(modPath, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Track which modules were scanned
	var scannedCount int32

	scanFn := func(ctx context.Context, target ports.Target) (*assessment.Assessment, error) {
		atomic.AddInt32(&scannedCount, 1)
		assess := assessment.NewAssessment(target.Path)
		assess.Complete()
		return assess, nil
	}

	scanner := NewParallelScanner(WithMaxWorkers(2))
	results, err := scanner.Scan(context.Background(), tempDir, modules, scanFn)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	if scannedCount != 3 {
		t.Errorf("expected 3 modules scanned, got %d", scannedCount)
	}
}

func TestParallelScanner_Scan_Empty(t *testing.T) {
	scanner := NewParallelScanner()
	results, err := scanner.Scan(context.Background(), ".", nil, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if results != nil {
		t.Errorf("expected nil results, got %v", results)
	}
}

func TestParallelScanner_Scan_WithErrors(t *testing.T) {
	modules := []Module{
		{Path: "success", Name: "github.com/test/success"},
		{Path: "failure", Name: "github.com/test/failure"},
	}

	scanFn := func(ctx context.Context, target ports.Target) (*assessment.Assessment, error) {
		if filepath.Base(target.Path) == "failure" {
			return nil, errors.New("scan failed")
		}
		assess := assessment.NewAssessment(target.Path)
		assess.Complete()
		return assess, nil
	}

	scanner := NewParallelScanner()
	results, err := scanner.Scan(context.Background(), ".", modules, scanFn)
	if err != nil {
		t.Fatalf("Scan should not fail overall: %v", err)
	}

	var successCount, failCount int
	for _, r := range results {
		if r.Error != nil {
			failCount++
		} else {
			successCount++
		}
	}

	if successCount != 1 {
		t.Errorf("expected 1 success, got %d", successCount)
	}
	if failCount != 1 {
		t.Errorf("expected 1 failure, got %d", failCount)
	}
}

func TestParallelScanner_Scan_ContextCancellation(t *testing.T) {
	modules := []Module{
		{Path: "mod-1", Name: "github.com/test/mod-1"},
		{Path: "mod-2", Name: "github.com/test/mod-2"},
	}

	ctx, cancel := context.WithCancel(context.Background())

	scanFn := func(ctx context.Context, target ports.Target) (*assessment.Assessment, error) {
		// Cancel after first scan starts
		cancel()
		time.Sleep(10 * time.Millisecond)
		return assessment.NewAssessment(target.Path), nil
	}

	scanner := NewParallelScanner(WithMaxWorkers(1))
	results, err := scanner.Scan(ctx, ".", modules, scanFn)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// At least one result should have context error
	var ctxErrors int
	for _, r := range results {
		if r.Error == context.Canceled {
			ctxErrors++
		}
	}

	if ctxErrors == 0 {
		t.Error("expected at least one context cancellation error")
	}
}

func TestParallelScanner_Progress(t *testing.T) {
	modules := []Module{
		{Path: "mod-1", Name: "github.com/test/mod-1"},
		{Path: "mod-2", Name: "github.com/test/mod-2"},
	}

	var progressCalls int32

	scanFn := func(ctx context.Context, target ports.Target) (*assessment.Assessment, error) {
		return assessment.NewAssessment(target.Path), nil
	}

	progressFn := func(mod Module, result *ModuleResult, completed, total int) {
		atomic.AddInt32(&progressCalls, 1)
	}

	scanner := NewParallelScanner(WithProgress(progressFn))
	_, err := scanner.Scan(context.Background(), ".", modules, scanFn)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if progressCalls != 2 {
		t.Errorf("expected 2 progress calls, got %d", progressCalls)
	}
}

func TestParallelScanner_ScanWithFilter(t *testing.T) {
	modules := []Module{
		{Path: "services/svc-a", Name: "github.com/test/svc-a"},
		{Path: "services/svc-b", Name: "github.com/test/svc-b"},
		{Path: "pkg/common", Name: "github.com/test/common"},
	}

	var scannedCount int32

	scanFn := func(ctx context.Context, target ports.Target) (*assessment.Assessment, error) {
		atomic.AddInt32(&scannedCount, 1)
		return assessment.NewAssessment(target.Path), nil
	}

	scanner := NewParallelScanner()
	_, err := scanner.ScanWithFilter(context.Background(), ".", modules, "services/*", scanFn)
	if err != nil {
		t.Fatalf("ScanWithFilter failed: %v", err)
	}

	if atomic.LoadInt32(&scannedCount) != 2 {
		t.Errorf("expected 2 modules scanned, got %d", scannedCount)
	}
}

func TestParallelScanner_ScanWithFilter_NoMatch(t *testing.T) {
	modules := []Module{
		{Path: "services/svc-a", Name: "github.com/test/svc-a"},
	}

	scanFn := func(ctx context.Context, target ports.Target) (*assessment.Assessment, error) {
		return assessment.NewAssessment(target.Path), nil
	}

	scanner := NewParallelScanner()
	_, err := scanner.ScanWithFilter(context.Background(), ".", modules, "nonexistent/*", scanFn)
	if err == nil {
		t.Error("expected error for no matching modules")
	}
}

func TestAggregate(t *testing.T) {
	// Create module results with findings
	results := []ModuleResult{
		{
			Module:     Module{Path: "svc-a", Name: "github.com/test/svc-a"},
			Assessment: createAssessmentWithFindings(2, finding.SeverityHigh),
		},
		{
			Module:     Module{Path: "svc-b", Name: "github.com/test/svc-b"},
			Assessment: createAssessmentWithFindings(3, finding.SeverityMedium),
		},
		{
			Module: Module{Path: "svc-c", Name: "github.com/test/svc-c"},
			Error:  errors.New("scan failed"),
		},
	}

	agg := Aggregate(results)

	if agg.TotalFindings != 5 {
		t.Errorf("expected 5 total findings, got %d", agg.TotalFindings)
	}

	if len(agg.SuccessfulModules) != 2 {
		t.Errorf("expected 2 successful modules, got %d", len(agg.SuccessfulModules))
	}

	if len(agg.FailedModules) != 1 {
		t.Errorf("expected 1 failed module, got %d", len(agg.FailedModules))
	}

	if agg.FindingsByModule["svc-a"] != 2 {
		t.Errorf("expected 2 findings for svc-a, got %d", agg.FindingsByModule["svc-a"])
	}

	if agg.FindingsByModule["svc-b"] != 3 {
		t.Errorf("expected 3 findings for svc-b, got %d", agg.FindingsByModule["svc-b"])
	}

	if agg.FindingsBySeverity[finding.SeverityHigh] != 2 {
		t.Errorf("expected 2 high severity, got %d", agg.FindingsBySeverity[finding.SeverityHigh])
	}

	if agg.FindingsBySeverity[finding.SeverityMedium] != 3 {
		t.Errorf("expected 3 medium severity, got %d", agg.FindingsBySeverity[finding.SeverityMedium])
	}
}

func TestAggregatedResult_AllFindings(t *testing.T) {
	results := []ModuleResult{
		{
			Module:     Module{Path: "svc-a"},
			Assessment: createAssessmentWithFindings(2, finding.SeverityHigh),
		},
		{
			Module:     Module{Path: "svc-b"},
			Assessment: createAssessmentWithFindings(3, finding.SeverityMedium),
		},
	}

	agg := Aggregate(results)
	allFindings := agg.AllFindings()

	if len(allFindings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(allFindings))
	}
}

func TestAggregatedResult_FindingsForModule(t *testing.T) {
	results := []ModuleResult{
		{
			Module:     Module{Path: "svc-a"},
			Assessment: createAssessmentWithFindings(2, finding.SeverityHigh),
		},
		{
			Module:     Module{Path: "svc-b"},
			Assessment: createAssessmentWithFindings(3, finding.SeverityMedium),
		},
	}

	agg := Aggregate(results)

	findingsA := agg.FindingsForModule("svc-a")
	if len(findingsA) != 2 {
		t.Errorf("expected 2 findings for svc-a, got %d", len(findingsA))
	}

	findingsB := agg.FindingsForModule("svc-b")
	if len(findingsB) != 3 {
		t.Errorf("expected 3 findings for svc-b, got %d", len(findingsB))
	}

	findingsC := agg.FindingsForModule("nonexistent")
	if findingsC != nil {
		t.Errorf("expected nil for nonexistent module, got %v", findingsC)
	}
}

func TestAggregatedResult_HasErrors(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		results := []ModuleResult{
			{Module: Module{Path: "svc-a"}, Assessment: assessment.NewAssessment("svc-a")},
		}
		agg := Aggregate(results)
		if agg.HasErrors() {
			t.Error("expected no errors")
		}
	})

	t.Run("with errors", func(t *testing.T) {
		results := []ModuleResult{
			{Module: Module{Path: "svc-a"}, Error: errors.New("failed")},
		}
		agg := Aggregate(results)
		if !agg.HasErrors() {
			t.Error("expected errors")
		}
	})
}

func TestAggregatedResult_Summary(t *testing.T) {
	results := []ModuleResult{
		{
			Module:     Module{Path: "svc-a"},
			Assessment: createAssessmentWithFindings(2, finding.SeverityHigh),
		},
		{
			Module: Module{Path: "svc-b"},
			Error:  errors.New("failed"),
		},
	}

	agg := Aggregate(results)
	summary := agg.Summary()

	expected := "Scanned 2 modules (1 successful, 1 failed), found 2 findings"
	if summary != expected {
		t.Errorf("expected summary %q, got %q", expected, summary)
	}
}

func TestMatchPrefix(t *testing.T) {
	tests := []struct {
		path     string
		prefix   string
		expected bool
	}{
		{"services/svc-a", "services/", true},
		{"services/svc-a", "services/*", true},
		{"pkg/common", "services/", false},
		// Note: filepath.Clean("services/") = "services", so exact match is true
		{"services", "services/", true},
		// Note: filepath.Clean("") = ".", so empty path doesn't match "."
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path+"_"+tt.prefix, func(t *testing.T) {
			result := matchPrefix(tt.path, tt.prefix)
			if result != tt.expected {
				t.Errorf("matchPrefix(%q, %q) = %v, want %v", tt.path, tt.prefix, result, tt.expected)
			}
		})
	}
}

// Helper function to create assessment with findings
func createAssessmentWithFindings(count int, severity finding.Severity) *assessment.Assessment {
	assess := assessment.NewAssessment("test")
	for i := 0; i < count; i++ {
		loc := finding.NewLocation("test.go", 10+i, 0, 0, 0)
		f := finding.NewFinding(
			finding.FindingTypeSAST,
			"test-engine",
			"TEST-001",
			"Test finding",
			severity,
			loc,
		)
		assess.AddFinding(f)
	}
	assess.Complete()
	return assess
}
