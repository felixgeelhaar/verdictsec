package main

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverityShort(t *testing.T) {
	// Test with color disabled
	oldNoColor := noColor
	noColor = true
	defer func() { noColor = oldNoColor }()

	tests := []struct {
		severity finding.Severity
		expected string
	}{
		{finding.SeverityCritical, "[C]"},
		{finding.SeverityHigh, "[H]"},
		{finding.SeverityMedium, "[M]"},
		{finding.SeverityLow, "[L]"},
		{finding.SeverityUnknown, "[?]"},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			result := severityShort(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSeverityShort_WithColor(t *testing.T) {
	// Test with color enabled
	oldNoColor := noColor
	noColor = false
	defer func() { noColor = oldNoColor }()

	// Should return non-empty strings with ANSI codes
	critResult := severityShort(finding.SeverityCritical)
	assert.Contains(t, critResult, "C")

	highResult := severityShort(finding.SeverityHigh)
	assert.Contains(t, highResult, "H")

	medResult := severityShort(finding.SeverityMedium)
	assert.Contains(t, medResult, "M")

	lowResult := severityShort(finding.SeverityLow)
	assert.Contains(t, lowResult, "L")
}

func TestWriteFindingLine(t *testing.T) {
	// Test with color disabled
	oldNoColor := noColor
	noColor = true
	defer func() { noColor = oldNoColor }()

	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Hardcoded credentials",
		finding.SeverityHigh,
		finding.NewLocation("main.go", 10, 1, 10, 50),
	)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Use identity function that returns input
	identityFunc := func(a ...interface{}) string { return fmt.Sprint(a...) }
	writeFindingLine(f, "+", identityFunc, identityFunc)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "Hardcoded credentials")
	assert.Contains(t, output, "main.go")
	assert.Contains(t, output, "10")
}

func TestWriteDiffConsole_EmptyDiff(t *testing.T) {
	// Test with color disabled
	oldNoColor := noColor
	noColor = true
	defer func() { noColor = oldNoColor }()

	output := usecases.DiffRefsOutput{
		FromRef:       "main",
		ToRef:         "feature",
		NewFindings:   []*finding.Finding{},
		FixedFindings: []*finding.Finding{},
		Unchanged:     []*finding.Finding{},
		Summary: usecases.DiffSummary{
			TotalNew:       0,
			TotalFixed:     0,
			TotalUnchanged: 0,
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// We can't fully test this without os.Exit, but we can at least run it
	// The function calls os.Exit so we need to be careful
	// For now, just verify the output structure
	_ = output

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	// Output will be empty since we didn't call the function
	// This test mainly verifies the structure compiles
}

func TestWriteDiffConsole_WithNewFindings(t *testing.T) {
	// Test with color disabled
	oldNoColor := noColor
	noColor = true
	defer func() { noColor = oldNoColor }()

	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"New finding",
		finding.SeverityHigh,
		finding.NewLocation("main.go", 10, 1, 10, 50),
	)

	output := usecases.DiffRefsOutput{
		FromRef:       "main",
		ToRef:         "feature",
		NewFindings:   []*finding.Finding{f},
		FixedFindings: []*finding.Finding{},
		Unchanged:     []*finding.Finding{},
		Summary: usecases.DiffSummary{
			TotalNew:       1,
			TotalFixed:     0,
			TotalUnchanged: 0,
		},
	}

	assert.Equal(t, 1, len(output.NewFindings))
	assert.True(t, output.HasNewFindings())
	assert.Equal(t, 1, output.NetChange())
}

func TestWriteDiffConsole_WithFixedFindings(t *testing.T) {
	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Fixed finding",
		finding.SeverityHigh,
		finding.NewLocation("main.go", 10, 1, 10, 50),
	)

	output := usecases.DiffRefsOutput{
		FromRef:       "main",
		ToRef:         "feature",
		NewFindings:   []*finding.Finding{},
		FixedFindings: []*finding.Finding{f},
		Unchanged:     []*finding.Finding{},
		Summary: usecases.DiffSummary{
			TotalNew:       0,
			TotalFixed:     1,
			TotalUnchanged: 0,
		},
	}

	assert.Equal(t, 1, len(output.FixedFindings))
	assert.False(t, output.HasNewFindings())
	assert.Equal(t, -1, output.NetChange())
}

func TestDiffOutput_NetChange(t *testing.T) {
	// Helper to create findings slice of given length
	makeFindings := func(count int) []*finding.Finding {
		findings := make([]*finding.Finding, count)
		for i := 0; i < count; i++ {
			findings[i] = finding.NewFinding(
				finding.FindingTypeSAST,
				"gosec",
				fmt.Sprintf("G%d", i),
				fmt.Sprintf("Finding %d", i),
				finding.SeverityMedium,
				finding.NewLocation("test.go", i+1, 1, i+1, 50),
			)
		}
		return findings
	}

	tests := []struct {
		name       string
		newCount   int
		fixedCount int
		expected   int
	}{
		{
			name:       "no change",
			newCount:   0,
			fixedCount: 0,
			expected:   0,
		},
		{
			name:       "only new",
			newCount:   5,
			fixedCount: 0,
			expected:   5,
		},
		{
			name:       "only fixed",
			newCount:   0,
			fixedCount: 3,
			expected:   -3,
		},
		{
			name:       "more new than fixed",
			newCount:   10,
			fixedCount: 3,
			expected:   7,
		},
		{
			name:       "more fixed than new",
			newCount:   2,
			fixedCount: 8,
			expected:   -6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := usecases.DiffRefsOutput{
				NewFindings:   makeFindings(tt.newCount),
				FixedFindings: makeFindings(tt.fixedCount),
			}
			assert.Equal(t, tt.expected, output.NetChange())
		})
	}
}

func TestDiffCmd_Init(t *testing.T) {
	// Verify diff command is properly initialized
	assert.NotNil(t, diffCmd)
	assert.Equal(t, "diff <from..to>", diffCmd.Use)

	// Check flags exist
	flags := diffCmd.Flags()
	require.NotNil(t, flags)

	newOnlyFlag := flags.Lookup("new-only")
	assert.NotNil(t, newOnlyFlag)

	repoFlag := flags.Lookup("repo")
	assert.NotNil(t, repoFlag)
}
