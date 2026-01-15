package vex

import (
	"context"
	"strings"
	"testing"

	domainvex "github.com/felixgeelhaar/verdictsec/internal/domain/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoader(t *testing.T) {
	loader := NewLoader()
	assert.NotNil(t, loader)
}

func TestLoader_LoadFromBytes_OpenVEX(t *testing.T) {
	loader := NewLoader()

	openVEXDoc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/vex/doc-001",
		"author": "security-team",
		"timestamp": "2024-01-15T10:00:00Z",
		"version": 1,
		"statements": [
			{
				"vulnerability": {"@id": "CVE-2024-1234"},
				"products": [{"@id": "pkg:golang/example.com/foo@v1.0.0"}],
				"status": "not_affected",
				"justification": "vulnerable_code_not_present",
				"impact_statement": "The vulnerable code path is not used"
			}
		]
	}`

	doc, err := loader.LoadFromBytes(context.Background(), []byte(openVEXDoc))
	require.NoError(t, err)
	require.NotNil(t, doc)

	assert.Equal(t, "https://example.com/vex/doc-001", doc.ID())
	assert.Equal(t, "openvex", doc.Format())
	assert.Equal(t, "security-team", doc.Author())
	assert.Equal(t, 1, doc.StatementCount())

	stmt := doc.Statements()[0]
	assert.Equal(t, "CVE-2024-1234", stmt.VulnID())
	assert.Equal(t, domainvex.StatusNotAffected, stmt.Status())
	assert.True(t, stmt.IsNotAffected())
	assert.True(t, stmt.ShouldSuppress())
}

func TestLoader_LoadFromBytes_CSAF(t *testing.T) {
	loader := NewLoader()

	csafDoc := `{
		"csaf_version": "2.0",
		"document": {
			"title": "Security Advisory",
			"tracking": {
				"id": "CSAF-2024-001",
				"current_release_date": "2024-01-15T10:00:00Z"
			}
		},
		"vulnerabilities": [
			{
				"cve": "CVE-2024-5678",
				"product_status": {
					"known_not_affected": ["product-1"],
					"fixed": ["product-2"]
				}
			}
		]
	}`

	doc, err := loader.LoadFromBytes(context.Background(), []byte(csafDoc))
	require.NoError(t, err)
	require.NotNil(t, doc)

	assert.Equal(t, "CSAF-2024-001", doc.ID())
	assert.Equal(t, "csaf", doc.Format())
	assert.Equal(t, 2, doc.StatementCount()) // not_affected + fixed = 2 statements

	suppressed := doc.SuppressedVulns()
	assert.Contains(t, suppressed, "CVE-2024-5678")
}

func TestLoader_LoadFromBytes_InvalidJSON(t *testing.T) {
	loader := NewLoader()

	_, err := loader.LoadFromBytes(context.Background(), []byte("invalid json"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestLoader_LoadFromReader(t *testing.T) {
	loader := NewLoader()

	openVEXDoc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "doc-002",
		"statements": []
	}`

	doc, err := loader.LoadFromReader(context.Background(), strings.NewReader(openVEXDoc))
	require.NoError(t, err)
	require.NotNil(t, doc)

	assert.Equal(t, "doc-002", doc.ID())
}

func TestLoader_LoadFromFile_InvalidPath(t *testing.T) {
	loader := NewLoader()

	_, err := loader.LoadFromFile(context.Background(), "../../../../../../../invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestLoader_LoadFromFile_NonExistent(t *testing.T) {
	loader := NewLoader()

	_, err := loader.LoadFromFile(context.Background(), "/nonexistent/vex.json")
	assert.Error(t, err)
}

func TestLoader_ParseOpenVEX_WithSubcomponents(t *testing.T) {
	loader := NewLoader()

	openVEXDoc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "doc-003",
		"statements": [
			{
				"vulnerability": {"name": "GHSA-1234-5678"},
				"products": [
					{
						"@id": "pkg:golang/example.com/app@v1.0.0",
						"subcomponents": [
							{"@id": "pkg:golang/example.com/lib@v0.5.0"}
						]
					}
				],
				"status": "fixed",
				"timestamp": "2024-01-15T12:00:00Z",
				"action_statement": "Update lib to v0.6.0"
			}
		]
	}`

	doc, err := loader.LoadFromBytes(context.Background(), []byte(openVEXDoc))
	require.NoError(t, err)
	require.NotNil(t, doc)

	stmt := doc.Statements()[0]
	assert.Equal(t, "GHSA-1234-5678", stmt.VulnID())
	assert.Equal(t, domainvex.StatusFixed, stmt.Status())
	assert.True(t, stmt.IsFixed())
	assert.Len(t, stmt.Subcomponents(), 1)
	assert.Equal(t, "Update lib to v0.6.0", stmt.ActionStatement())
}

func TestLoader_ParseCSAF_MultipleStatuses(t *testing.T) {
	loader := NewLoader()

	csafDoc := `{
		"csaf_version": "2.0",
		"document": {
			"tracking": {"id": "CSAF-002"}
		},
		"vulnerabilities": [
			{
				"cve": "CVE-2024-1111",
				"product_status": {
					"known_not_affected": ["product-a"],
					"under_investigation": ["product-b"]
				}
			},
			{
				"cve": "CVE-2024-2222",
				"product_status": {
					"fixed": ["product-c"]
				}
			}
		]
	}`

	doc, err := loader.LoadFromBytes(context.Background(), []byte(csafDoc))
	require.NoError(t, err)
	require.NotNil(t, doc)

	// Should have 3 statements total
	assert.Equal(t, 3, doc.StatementCount())

	// Check suppressed (not_affected + fixed)
	suppressed := doc.SuppressedVulns()
	assert.Contains(t, suppressed, "CVE-2024-1111") // not_affected
	assert.Contains(t, suppressed, "CVE-2024-2222") // fixed

	// Check not_affected list
	notAffected := doc.NotAffectedVulns()
	assert.Len(t, notAffected, 1)

	// Check fixed list
	fixed := doc.FixedVulns()
	assert.Len(t, fixed, 1)
}

func TestLoader_ParseOpenVEX_InvalidStatus(t *testing.T) {
	loader := NewLoader()

	// Should skip statements with invalid status
	openVEXDoc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "doc-004",
		"statements": [
			{
				"vulnerability": {"@id": "CVE-2024-VALID"},
				"status": "not_affected"
			},
			{
				"vulnerability": {"@id": "CVE-2024-INVALID"},
				"status": "invalid_status"
			}
		]
	}`

	doc, err := loader.LoadFromBytes(context.Background(), []byte(openVEXDoc))
	require.NoError(t, err)
	require.NotNil(t, doc)

	// Should only have 1 statement (invalid status skipped)
	assert.Equal(t, 1, doc.StatementCount())
	assert.Equal(t, "CVE-2024-VALID", doc.Statements()[0].VulnID())
}
