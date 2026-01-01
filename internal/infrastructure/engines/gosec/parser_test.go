package gosec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewParser(t *testing.T) {
	parser := NewParser()
	assert.NotNil(t, parser)
}

func TestParser_Parse_EmptyData(t *testing.T) {
	parser := NewParser()

	findings, err := parser.Parse([]byte{})

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParser_Parse_ValidOutput(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"Issues": [
			{
				"severity": "HIGH",
				"confidence": "HIGH",
				"cwe": {"id": "327", "url": "https://cwe.mitre.org/data/definitions/327.html"},
				"rule_id": "G401",
				"details": "Use of weak cryptographic primitive",
				"file": "/path/to/main.go",
				"code": "md5.Sum(data)",
				"line": "42",
				"column": "10",
				"nosec": false
			}
		],
		"Stats": {
			"files": 10,
			"lines": 500,
			"nosec": 1,
			"found": 1
		}
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "G401", f.RuleID)
	assert.Equal(t, "Use of weak cryptographic primitive", f.Message)
	assert.Equal(t, "HIGH", f.Severity)
	assert.Equal(t, "HIGH", f.Confidence)
	assert.Equal(t, "/path/to/main.go", f.File)
	assert.Equal(t, 42, f.StartLine)
	assert.Equal(t, 10, f.StartColumn)
	assert.Equal(t, "md5.Sum(data)", f.Snippet)
	assert.Equal(t, "327", f.Metadata["cwe_id"])
	assert.Equal(t, "https://cwe.mitre.org/data/definitions/327.html", f.Metadata["cwe_url"])
}

func TestParser_Parse_MultipleIssues(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"Issues": [
			{
				"severity": "HIGH",
				"confidence": "HIGH",
				"cwe": {"id": "327"},
				"rule_id": "G401",
				"details": "Use of weak cryptographic primitive",
				"file": "/path/to/main.go",
				"code": "md5.Sum(data)",
				"line": "42",
				"column": "10",
				"nosec": false
			},
			{
				"severity": "MEDIUM",
				"confidence": "MEDIUM",
				"cwe": {"id": "78"},
				"rule_id": "G204",
				"details": "Subprocess launched with variable",
				"file": "/path/to/exec.go",
				"code": "exec.Command(cmd)",
				"line": "15",
				"column": "5",
				"nosec": false
			}
		],
		"Stats": {"files": 10, "lines": 500, "nosec": 0, "found": 2}
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	assert.Len(t, findings, 2)
	assert.Equal(t, "G401", findings[0].RuleID)
	assert.Equal(t, "G204", findings[1].RuleID)
}

func TestParser_Parse_NosecIssuesSkipped(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"Issues": [
			{
				"severity": "HIGH",
				"confidence": "HIGH",
				"cwe": {"id": "327"},
				"rule_id": "G401",
				"details": "Use of weak cryptographic primitive",
				"file": "/path/to/main.go",
				"code": "md5.Sum(data)",
				"line": "42",
				"column": "10",
				"nosec": true
			},
			{
				"severity": "MEDIUM",
				"confidence": "MEDIUM",
				"cwe": {"id": "78"},
				"rule_id": "G204",
				"details": "Subprocess launched with variable",
				"file": "/path/to/exec.go",
				"code": "exec.Command(cmd)",
				"line": "15",
				"column": "5",
				"nosec": false
			}
		],
		"Stats": {"files": 10, "lines": 500, "nosec": 1, "found": 2}
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "G204", findings[0].RuleID)
}

func TestParser_Parse_InvalidJSON(t *testing.T) {
	parser := NewParser()
	input := []byte(`{invalid json}`)

	findings, err := parser.Parse(input)

	assert.Error(t, err)
	assert.Nil(t, findings)
	assert.Contains(t, err.Error(), "failed to unmarshal gosec output")
}

func TestParser_Parse_EmptyIssues(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"Issues": [],
		"Stats": {"files": 10, "lines": 500, "nosec": 0, "found": 0}
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParser_Parse_MultiLineRange(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"Issues": [
			{
				"severity": "HIGH",
				"confidence": "HIGH",
				"cwe": {"id": "327"},
				"rule_id": "G401",
				"details": "Issue spanning multiple lines",
				"file": "/path/to/main.go",
				"code": "multiline code",
				"line": "10-15",
				"column": "5",
				"nosec": false
			}
		],
		"Stats": {"files": 1, "lines": 100, "nosec": 0, "found": 1}
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, 10, findings[0].StartLine)
}

func TestParser_Parse_NoCWE(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"Issues": [
			{
				"severity": "LOW",
				"confidence": "LOW",
				"cwe": {},
				"rule_id": "G104",
				"details": "Errors not checked",
				"file": "/path/to/main.go",
				"code": "_ = doSomething()",
				"line": "20",
				"column": "1",
				"nosec": false
			}
		],
		"Stats": {"files": 1, "lines": 100, "nosec": 0, "found": 1}
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Empty(t, findings[0].Metadata["cwe_id"])
}

func TestParser_ParseStats(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"Issues": [],
		"Stats": {"files": 42, "lines": 1234, "nosec": 5, "found": 10}
	}`)

	stats, err := parser.ParseStats(input)

	require.NoError(t, err)
	assert.Equal(t, 42, stats.Files)
	assert.Equal(t, 1234, stats.Lines)
	assert.Equal(t, 5, stats.Nosec)
	assert.Equal(t, 10, stats.Found)
}

func TestParser_ParseStats_EmptyData(t *testing.T) {
	parser := NewParser()

	stats, err := parser.ParseStats([]byte{})

	require.NoError(t, err)
	assert.Equal(t, GosecStats{}, stats)
}

func TestParser_ParseStats_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.ParseStats([]byte(`{invalid}`))

	assert.Error(t, err)
}

func TestParser_GetIssueCount(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"Issues": [
			{"severity": "HIGH", "confidence": "HIGH", "cwe": {}, "rule_id": "G401", "details": "Issue 1", "file": "a.go", "code": "", "line": "1", "column": "1", "nosec": false},
			{"severity": "MEDIUM", "confidence": "HIGH", "cwe": {}, "rule_id": "G402", "details": "Issue 2", "file": "b.go", "code": "", "line": "2", "column": "1", "nosec": false},
			{"severity": "LOW", "confidence": "LOW", "cwe": {}, "rule_id": "G403", "details": "Issue 3", "file": "c.go", "code": "", "line": "3", "column": "1", "nosec": true}
		],
		"Stats": {"files": 3, "lines": 300, "nosec": 1, "found": 3}
	}`)

	count, err := parser.GetIssueCount(input)

	require.NoError(t, err)
	assert.Equal(t, 2, count) // Only 2 because one has nosec=true
}

func TestParser_GetIssueCount_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.GetIssueCount([]byte(`{invalid}`))

	assert.Error(t, err)
}

func TestParseLineNumber(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"simple number", "42", 42},
		{"range", "10-15", 10},
		{"zero", "0", 0},
		{"empty", "", 1},
		{"invalid", "abc", 1},
		{"with dash at end", "5-", 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLineNumber(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
