package govulncheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewParser(t *testing.T) {
	parser := NewParser()
	assert.NotNil(t, parser)
	assert.NotNil(t, parser.osvCache)
}

func TestParser_Parse_EmptyData(t *testing.T) {
	parser := NewParser()

	findings, err := parser.Parse([]byte{})

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParser_Parse_ValidOutput(t *testing.T) {
	parser := NewParser()
	input := []byte(`{"osv":{"id":"GO-2023-1234","summary":"Test vulnerability","aliases":["CVE-2023-1234"],"affected":[{"package":{"name":"example.com/vulnerable"}}]}}
{"finding":{"osv":"GO-2023-1234","trace":[{"module":"example.com/vulnerable","version":"v1.0.0","package":"example.com/vulnerable/pkg","function":"DoSomething","position":{"filename":"pkg/file.go","line":42,"column":10}}]}}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "GO-2023-1234", f.RuleID)
	assert.Equal(t, "Test vulnerability", f.Message)
	assert.Equal(t, "HIGH", f.Severity)
	assert.Equal(t, "pkg/file.go", f.File)
	assert.Equal(t, 42, f.StartLine)
	assert.Equal(t, "CVE-2023-1234", f.Metadata["cve_id"])
	assert.Equal(t, "GO-2023-1234", f.Metadata["osv_id"])
}

func TestParser_Parse_MultipleFindings(t *testing.T) {
	parser := NewParser()
	input := []byte(`{"osv":{"id":"GO-2023-0001","summary":"Vuln 1"}}
{"osv":{"id":"GO-2023-0002","summary":"Vuln 2"}}
{"finding":{"osv":"GO-2023-0001","trace":[{"module":"mod1","version":"v1.0.0","package":"pkg1"}]}}
{"finding":{"osv":"GO-2023-0002","trace":[{"module":"mod2","version":"v2.0.0","package":"pkg2"}]}}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	assert.Len(t, findings, 2)
}

func TestParser_Parse_FindingWithoutPosition(t *testing.T) {
	parser := NewParser()
	input := []byte(`{"osv":{"id":"GO-2023-1234","summary":"Test vuln"}}
{"finding":{"osv":"GO-2023-1234","trace":[{"module":"example.com/mod","version":"v1.0.0","package":"example.com/mod/pkg"}]}}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "example.com/mod/pkg", f.File) // Falls back to package
}

func TestParser_Parse_ProgressMessagesIgnored(t *testing.T) {
	parser := NewParser()
	input := []byte(`{"progress":{"message":"Scanning..."}}
{"osv":{"id":"GO-2023-1234","summary":"Test"}}
{"finding":{"osv":"GO-2023-1234","trace":[{"module":"mod","version":"v1.0.0","package":"pkg"}]}}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	assert.Len(t, findings, 1)
}

func TestParser_Parse_ConfigMessagesIgnored(t *testing.T) {
	parser := NewParser()
	input := []byte(`{"config":{"go_version":"go1.21","scanner_name":"govulncheck"}}
{"osv":{"id":"GO-2023-1234","summary":"Test"}}
{"finding":{"osv":"GO-2023-1234","trace":[{"module":"mod","version":"v1.0.0","package":"pkg"}]}}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	assert.Len(t, findings, 1)
}

func TestParser_Parse_NonJSONLinesIgnored(t *testing.T) {
	parser := NewParser()
	input := []byte(`Some non-JSON output
{"osv":{"id":"GO-2023-1234","summary":"Test"}}
More non-JSON
{"finding":{"osv":"GO-2023-1234","trace":[{"module":"mod","version":"v1.0.0","package":"pkg"}]}}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	assert.Len(t, findings, 1)
}

func TestParser_GetVulnerabilityCount(t *testing.T) {
	parser := NewParser()
	input := []byte(`{"osv":{"id":"GO-2023-0001"}}
{"osv":{"id":"GO-2023-0002"}}
{"finding":{"osv":"GO-2023-0001","trace":[{"module":"m","version":"v1","package":"p"}]}}
{"finding":{"osv":"GO-2023-0002","trace":[{"module":"m","version":"v1","package":"p"}]}}`)

	count, err := parser.GetVulnerabilityCount(input)

	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestParser_findingToRaw_NilFinding(t *testing.T) {
	parser := NewParser()

	result := parser.findingToRaw(nil)

	assert.Nil(t, result)
}

func TestParser_findingToRaw_EmptyTrace(t *testing.T) {
	parser := NewParser()
	finding := &FindingMessage{
		OSV:   "GO-2023-1234",
		Trace: []TraceEntry{},
	}

	result := parser.findingToRaw(finding)

	assert.Nil(t, result)
}
