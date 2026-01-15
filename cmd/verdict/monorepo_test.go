package main

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/workspace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMonorepoCmd_Init(t *testing.T) {
	// Verify monorepo command is properly initialized
	assert.NotNil(t, monorepoCmd)
	assert.Equal(t, "monorepo [path]", monorepoCmd.Use)

	// Check flags exist
	flags := monorepoCmd.Flags()
	require.NotNil(t, flags)

	modulesFlag := flags.Lookup("modules")
	assert.NotNil(t, modulesFlag)

	filterFlag := flags.Lookup("filter")
	assert.NotNil(t, filterFlag)

	byModuleFlag := flags.Lookup("by-module")
	assert.NotNil(t, byModuleFlag)

	workersFlag := flags.Lookup("workers")
	assert.NotNil(t, workersFlag)
}

func TestFilterModulesByPath(t *testing.T) {
	modules := []workspace.Module{
		{Path: "./svc/a", Name: "a"},
		{Path: "./svc/b", Name: "b"},
		{Path: "./lib/common", Name: "common"},
		{Path: "./tools/cli", Name: "cli"},
	}

	tests := []struct {
		name     string
		paths    []string
		expected int
	}{
		{
			name:     "filter by single path",
			paths:    []string{"./svc/a"},
			expected: 1,
		},
		{
			name:     "filter by multiple paths",
			paths:    []string{"./svc/a", "./svc/b"},
			expected: 2,
		},
		{
			name:     "filter by name",
			paths:    []string{"common"},
			expected: 1,
		},
		{
			name:     "filter by mixed path and name",
			paths:    []string{"./svc/a", "cli"},
			expected: 2,
		},
		{
			name:     "no matches",
			paths:    []string{"./nonexistent"},
			expected: 0,
		},
		{
			name:     "empty filter",
			paths:    []string{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := filterModulesByPath(modules, tt.paths)
			assert.Len(t, filtered, tt.expected)
		})
	}
}

func TestFilterModulesByPath_PreservesOrder(t *testing.T) {
	modules := []workspace.Module{
		{Path: "./a", Name: "a"},
		{Path: "./b", Name: "b"},
		{Path: "./c", Name: "c"},
	}

	filtered := filterModulesByPath(modules, []string{"./a", "./c"})

	require.Len(t, filtered, 2)
	assert.Equal(t, "./a", filtered[0].Path)
	assert.Equal(t, "./c", filtered[1].Path)
}

func TestBuildCombinedAssessment(t *testing.T) {
	// Create module results with findings
	f1 := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Finding 1",
		finding.SeverityHigh,
		finding.NewLocation("svc/a/main.go", 10, 1, 10, 50),
	)

	f2 := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G102",
		"Finding 2",
		finding.SeverityMedium,
		finding.NewLocation("svc/b/main.go", 20, 1, 20, 50),
	)

	assess1 := assessment.NewAssessment("./svc/a")
	assess1.AddFinding(f1)
	assess1.Complete()

	assess2 := assessment.NewAssessment("./svc/b")
	assess2.AddFinding(f2)
	assess2.Complete()

	agg := &workspace.AggregatedResult{
		Modules: []workspace.ModuleResult{
			{
				Module:     workspace.Module{Path: "./svc/a", Name: "a"},
				Assessment: assess1,
			},
			{
				Module:     workspace.Module{Path: "./svc/b", Name: "b"},
				Assessment: assess2,
			},
		},
	}

	combined := buildCombinedAssessment(agg, "./root")

	assert.NotNil(t, combined)
	assert.Equal(t, 2, len(combined.Findings()))
}

func TestBuildCombinedAssessment_EmptyResults(t *testing.T) {
	agg := &workspace.AggregatedResult{
		Modules: []workspace.ModuleResult{},
	}

	combined := buildCombinedAssessment(agg, "./root")

	assert.NotNil(t, combined)
	assert.Equal(t, 0, len(combined.Findings()))
}

func TestBuildCombinedAssessment_WithErrors(t *testing.T) {
	// Module with error should not contribute findings
	assess1 := assessment.NewAssessment("./svc/a")
	assess1.Complete()

	agg := &workspace.AggregatedResult{
		Modules: []workspace.ModuleResult{
			{
				Module:     workspace.Module{Path: "./svc/a", Name: "a"},
				Assessment: assess1,
				Error:      nil,
			},
			{
				Module: workspace.Module{Path: "./svc/b", Name: "b"},
				Error:  assert.AnError,
			},
		},
	}

	combined := buildCombinedAssessment(agg, "./root")

	assert.NotNil(t, combined)
	// Only findings from successful modules should be included
	assert.Equal(t, 0, len(combined.Findings()))
}

func TestMonorepoFlags_Defaults(t *testing.T) {
	flags := monorepoCmd.Flags()

	workersFlag := flags.Lookup("workers")
	assert.Equal(t, "4", workersFlag.DefValue)

	byModuleFlag := flags.Lookup("by-module")
	assert.Equal(t, "false", byModuleFlag.DefValue)
}
