package staticcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewParser(t *testing.T) {
	parser := NewParser()
	assert.NotNil(t, parser)
}

func TestParser_Parse_EmptyInput(t *testing.T) {
	parser := NewParser()

	findings, err := parser.Parse([]byte{})

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParser_Parse_SingleIssue(t *testing.T) {
	parser := NewParser()

	input := []byte(`{"code":"U1000","severity":"error","location":{"file":"/path/to/main.go","line":11,"column":6},"end":{"file":"","line":0,"column":0},"message":"func unused is unused"}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "U1000", f.RuleID)
	assert.Equal(t, "func unused is unused", f.Message)
	assert.Equal(t, "error", f.Severity)
	assert.Equal(t, "HIGH", f.Confidence)
	assert.Equal(t, "/path/to/main.go", f.File)
	assert.Equal(t, 11, f.StartLine)
	assert.Equal(t, 6, f.StartColumn)
}

func TestParser_Parse_MultipleIssues(t *testing.T) {
	parser := NewParser()

	input := []byte(`{"code":"U1000","severity":"error","location":{"file":"/path/to/main.go","line":11,"column":6},"end":{"file":"","line":0,"column":0},"message":"func unused is unused"}
{"code":"U1000","severity":"error","location":{"file":"/path/to/utils.go","line":25,"column":5},"end":{"file":"","line":0,"column":0},"message":"type UnusedType is unused"}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 2)

	assert.Equal(t, "/path/to/main.go", findings[0].File)
	assert.Equal(t, "/path/to/utils.go", findings[1].File)
}

func TestParser_Parse_WithEndLocation(t *testing.T) {
	parser := NewParser()

	input := []byte(`{"code":"U1000","severity":"error","location":{"file":"/path/to/main.go","line":11,"column":6},"end":{"file":"/path/to/main.go","line":15,"column":2},"message":"func unused is unused"}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, 11, f.StartLine)
	assert.Equal(t, 6, f.StartColumn)
	assert.Equal(t, 15, f.EndLine)
	assert.Equal(t, 2, f.EndColumn)
}

func TestParser_Parse_NoEndLocation(t *testing.T) {
	parser := NewParser()

	input := []byte(`{"code":"U1000","severity":"error","location":{"file":"/path/to/main.go","line":11,"column":6},"end":{"file":"","line":0,"column":0},"message":"func unused is unused"}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	// When end location is not provided, should default to start line
	assert.Equal(t, 11, f.EndLine)
	// End column should have a reasonable default
	assert.Greater(t, f.EndColumn, 0)
}

func TestParser_Parse_Metadata(t *testing.T) {
	parser := NewParser()

	input := []byte(`{"code":"U1000","severity":"error","location":{"file":"/path/to/main.go","line":11,"column":6},"end":{"file":"","line":0,"column":0},"message":"func unused is unused"}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Should have check_code in metadata
	assert.Equal(t, "U1000", findings[0].Metadata["check_code"])
}

func TestParser_Parse_InvalidJSON(t *testing.T) {
	parser := NewParser()

	input := []byte(`not valid json`)

	_, err := parser.Parse(input)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

func TestParser_Parse_PartiallyInvalidJSON(t *testing.T) {
	parser := NewParser()

	// First line valid, second line invalid
	input := []byte(`{"code":"U1000","severity":"error","location":{"file":"/path/to/main.go","line":11,"column":6},"end":{"file":"","line":0,"column":0},"message":"func unused is unused"}
not valid json`)

	_, err := parser.Parse(input)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "line 2")
}

func TestParser_Parse_EmptyLines(t *testing.T) {
	parser := NewParser()

	input := []byte(`{"code":"U1000","severity":"error","location":{"file":"/path/to/main.go","line":11,"column":6},"end":{"file":"","line":0,"column":0},"message":"func unused is unused"}

{"code":"U1000","severity":"error","location":{"file":"/path/to/utils.go","line":25,"column":5},"end":{"file":"","line":0,"column":0},"message":"type UnusedType is unused"}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 2)
}

func TestParser_GetIssueCount(t *testing.T) {
	parser := NewParser()

	input := []byte(`{"code":"U1000","severity":"error","location":{"file":"/path/to/main.go","line":11,"column":6},"end":{"file":"","line":0,"column":0},"message":"func unused is unused"}
{"code":"U1000","severity":"error","location":{"file":"/path/to/utils.go","line":25,"column":5},"end":{"file":"","line":0,"column":0},"message":"type UnusedType is unused"}`)

	count, err := parser.GetIssueCount(input)

	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestParser_GetIssueCount_Empty(t *testing.T) {
	parser := NewParser()

	count, err := parser.GetIssueCount([]byte{})

	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
