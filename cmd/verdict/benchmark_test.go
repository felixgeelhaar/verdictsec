package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateStats(t *testing.T) {
	tests := []struct {
		name     string
		timings  []time.Duration
		wantNil  bool
		checkMin time.Duration
		checkMax time.Duration
	}{
		{
			name:    "empty timings returns nil",
			timings: []time.Duration{},
			wantNil: true,
		},
		{
			name:     "single timing",
			timings:  []time.Duration{100 * time.Millisecond},
			wantNil:  false,
			checkMin: 100 * time.Millisecond,
			checkMax: 100 * time.Millisecond,
		},
		{
			name: "multiple timings",
			timings: []time.Duration{
				100 * time.Millisecond,
				200 * time.Millisecond,
				300 * time.Millisecond,
				400 * time.Millisecond,
				500 * time.Millisecond,
			},
			wantNil:  false,
			checkMin: 100 * time.Millisecond,
			checkMax: 500 * time.Millisecond,
		},
		{
			name: "unsorted timings get sorted",
			timings: []time.Duration{
				500 * time.Millisecond,
				100 * time.Millisecond,
				300 * time.Millisecond,
			},
			wantNil:  false,
			checkMin: 100 * time.Millisecond,
			checkMax: 500 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := calculateStats(tt.timings)
			if tt.wantNil {
				assert.Nil(t, stats)
				return
			}
			require.NotNil(t, stats)
			assert.Equal(t, tt.checkMin, stats.Min)
			assert.Equal(t, tt.checkMax, stats.Max)
			// Mean should be between min and max
			assert.GreaterOrEqual(t, stats.Mean, stats.Min)
			assert.LessOrEqual(t, stats.Mean, stats.Max)
			// Percentiles should be in order
			assert.LessOrEqual(t, stats.P50, stats.P95)
			assert.LessOrEqual(t, stats.P95, stats.P99)
		})
	}
}

func TestCalculateStats_MeanCalculation(t *testing.T) {
	timings := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		300 * time.Millisecond,
	}

	stats := calculateStats(timings)
	require.NotNil(t, stats)

	// Mean of 100, 200, 300 should be 200ms
	assert.Equal(t, 200*time.Millisecond, stats.Mean)
}

func TestPercentile(t *testing.T) {
	tests := []struct {
		name     string
		sorted   []time.Duration
		p        int
		expected time.Duration
	}{
		{
			name:     "empty slice returns 0",
			sorted:   []time.Duration{},
			p:        50,
			expected: 0,
		},
		{
			name:     "single element returns it",
			sorted:   []time.Duration{100 * time.Millisecond},
			p:        50,
			expected: 100 * time.Millisecond,
		},
		{
			name: "p0 returns first",
			sorted: []time.Duration{
				100 * time.Millisecond,
				200 * time.Millisecond,
				300 * time.Millisecond,
			},
			p:        0,
			expected: 100 * time.Millisecond,
		},
		{
			name: "p100 returns last",
			sorted: []time.Duration{
				100 * time.Millisecond,
				200 * time.Millisecond,
				300 * time.Millisecond,
			},
			p:        100,
			expected: 300 * time.Millisecond,
		},
		{
			name: "p50 returns middle",
			sorted: []time.Duration{
				100 * time.Millisecond,
				200 * time.Millisecond,
				300 * time.Millisecond,
				400 * time.Millisecond,
				500 * time.Millisecond,
			},
			p:        50,
			expected: 300 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := percentile(tt.sorted, tt.p)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRepeatString(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		n        int
		expected string
	}{
		{
			name:     "zero repeats",
			s:        "-",
			n:        0,
			expected: "",
		},
		{
			name:     "one repeat",
			s:        "-",
			n:        1,
			expected: "-",
		},
		{
			name:     "five repeats",
			s:        "-",
			n:        5,
			expected: "-----",
		},
		{
			name:     "multi-char string",
			s:        "ab",
			n:        3,
			expected: "ababab",
		},
		{
			name:     "empty string",
			s:        "",
			n:        5,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := repeatString(tt.s, tt.n)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOutputBenchmarkJSON(t *testing.T) {
	result := &BenchmarkResult{
		Target:        "./test",
		Iterations:    5,
		WarmupRuns:    1,
		TotalDuration: 10 * time.Second,
		EngineResults: map[string]*EngineResult{
			"gosec": {
				EngineID:  "gosec",
				Available: true,
				Stats: &Stats{
					Min:  100 * time.Millisecond,
					Max:  200 * time.Millisecond,
					Mean: 150 * time.Millisecond,
					P50:  150 * time.Millisecond,
					P95:  190 * time.Millisecond,
					P99:  200 * time.Millisecond,
				},
			},
		},
		OverallStats: &Stats{
			Min:  500 * time.Millisecond,
			Max:  1 * time.Second,
			Mean: 750 * time.Millisecond,
			P50:  750 * time.Millisecond,
			P95:  900 * time.Millisecond,
			P99:  1 * time.Second,
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputBenchmarkJSON(result)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Verify it's valid JSON
	var parsed BenchmarkResult
	err = json.Unmarshal([]byte(output), &parsed)
	require.NoError(t, err)

	assert.Equal(t, "./test", parsed.Target)
	assert.Equal(t, 5, parsed.Iterations)
}

func TestOutputBenchmarkText(t *testing.T) {
	result := &BenchmarkResult{
		Target:        "./test",
		Iterations:    5,
		WarmupRuns:    1,
		TotalDuration: 10 * time.Second,
		EngineResults: map[string]*EngineResult{
			"gosec": {
				EngineID:  "gosec",
				Available: true,
				Stats: &Stats{
					Min:  100 * time.Millisecond,
					Max:  200 * time.Millisecond,
					Mean: 150 * time.Millisecond,
					P50:  150 * time.Millisecond,
					P95:  190 * time.Millisecond,
					P99:  200 * time.Millisecond,
				},
			},
			"unavailable": {
				EngineID:  "unavailable",
				Available: false,
			},
		},
		OverallStats: &Stats{
			Min:  500 * time.Millisecond,
			Max:  1 * time.Second,
			Mean: 750 * time.Millisecond,
			P50:  750 * time.Millisecond,
			P95:  900 * time.Millisecond,
			P99:  1 * time.Second,
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputBenchmarkText(result)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Verify output contains expected sections
	assert.Contains(t, output, "Results")
	assert.Contains(t, output, "Total benchmark time")
	assert.Contains(t, output, "Overall Scan Statistics")
	assert.Contains(t, output, "Per-Engine Statistics")
	assert.Contains(t, output, "gosec")
	assert.Contains(t, output, "(not available)")
}

func TestOutputBenchmarkText_EnginesOnly(t *testing.T) {
	// Save and modify global flag
	oldBenchEnginesOnly := benchEnginesOnly
	benchEnginesOnly = true
	defer func() { benchEnginesOnly = oldBenchEnginesOnly }()

	result := &BenchmarkResult{
		Target:        "./test",
		Iterations:    5,
		TotalDuration: 10 * time.Second,
		EngineResults: map[string]*EngineResult{
			"gosec": {
				EngineID:  "gosec",
				Available: true,
				Stats: &Stats{
					Min:  100 * time.Millisecond,
					Max:  200 * time.Millisecond,
					Mean: 150 * time.Millisecond,
					P50:  150 * time.Millisecond,
					P95:  190 * time.Millisecond,
					P99:  200 * time.Millisecond,
				},
			},
		},
		OverallStats: &Stats{
			Min:  500 * time.Millisecond,
			Max:  1 * time.Second,
			Mean: 750 * time.Millisecond,
			P50:  750 * time.Millisecond,
			P95:  900 * time.Millisecond,
			P99:  1 * time.Second,
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputBenchmarkText(result)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Should NOT contain overall stats when engines-only
	assert.NotContains(t, output, "Overall Scan Statistics")
	assert.Contains(t, output, "Per-Engine Statistics")
}

func TestOutputBenchmarkText_NoData(t *testing.T) {
	result := &BenchmarkResult{
		Target:        "./test",
		Iterations:    5,
		TotalDuration: 10 * time.Second,
		EngineResults: map[string]*EngineResult{
			"gosec": {
				EngineID:  "gosec",
				Available: true,
				Stats:     nil, // No data
			},
		},
		OverallStats: &Stats{
			Min:  500 * time.Millisecond,
			Max:  1 * time.Second,
			Mean: 750 * time.Millisecond,
			P50:  750 * time.Millisecond,
			P95:  900 * time.Millisecond,
			P99:  1 * time.Second,
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputBenchmarkText(result)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "(no data)")
}

func TestBenchmarkResult_Structure(t *testing.T) {
	result := BenchmarkResult{
		Target:        "./test",
		Iterations:    10,
		WarmupRuns:    2,
		TotalDuration: 5 * time.Second,
		EngineResults: make(map[string]*EngineResult),
		OverallStats:  nil,
	}

	assert.Equal(t, "./test", result.Target)
	assert.Equal(t, 10, result.Iterations)
	assert.Equal(t, 2, result.WarmupRuns)
	assert.Equal(t, 5*time.Second, result.TotalDuration)
}

func TestEngineResult_Structure(t *testing.T) {
	result := EngineResult{
		EngineID:  "gosec",
		Available: true,
		Timings:   []time.Duration{100 * time.Millisecond, 200 * time.Millisecond},
		Stats:     nil,
	}

	assert.Equal(t, "gosec", result.EngineID)
	assert.True(t, result.Available)
	assert.Len(t, result.Timings, 2)
}

func TestStats_Structure(t *testing.T) {
	stats := Stats{
		Min:    100 * time.Millisecond,
		Max:    500 * time.Millisecond,
		Mean:   300 * time.Millisecond,
		P50:    300 * time.Millisecond,
		P95:    450 * time.Millisecond,
		P99:    480 * time.Millisecond,
		StdDev: 50 * time.Millisecond,
	}

	assert.Equal(t, 100*time.Millisecond, stats.Min)
	assert.Equal(t, 500*time.Millisecond, stats.Max)
	assert.Equal(t, 300*time.Millisecond, stats.Mean)
}
