package cyclonedx

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

func TestParser_Parse_ValidBOM(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1,
		"components": [
			{
				"type": "library",
				"bom-ref": "pkg:golang/github.com/example/pkg@v1.0.0",
				"name": "github.com/example/pkg",
				"version": "v1.0.0",
				"purl": "pkg:golang/github.com/example/pkg@v1.0.0",
				"licenses": [
					{"license": {"id": "MIT"}}
				]
			}
		]
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "sbom-component", f.RuleID)
	assert.Contains(t, f.Message, "github.com/example/pkg")
	assert.Contains(t, f.Message, "v1.0.0")
	assert.Equal(t, "library", f.Metadata["component_type"])
	assert.Equal(t, "MIT", f.Metadata["license"])
}

func TestParser_Parse_MultipleComponents(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{"type": "library", "name": "pkg1", "version": "v1.0.0", "bom-ref": "ref1"},
			{"type": "library", "name": "pkg2", "version": "v2.0.0", "bom-ref": "ref2"},
			{"type": "library", "name": "pkg3", "version": "v3.0.0", "bom-ref": "ref3"}
		]
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	assert.Len(t, findings, 3)
}

func TestParser_Parse_WithHashes(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"components": [
			{
				"type": "library",
				"name": "pkg",
				"version": "v1.0.0",
				"bom-ref": "ref",
				"hashes": [
					{"alg": "SHA-256", "content": "abc123"}
				]
			}
		]
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "abc123", findings[0].Metadata["hash_SHA-256"])
}

func TestParser_Parse_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.Parse([]byte(`{invalid}`))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal CycloneDX output")
}

func TestParser_ParseBOM(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1,
		"metadata": {
			"timestamp": "2024-01-01T00:00:00Z"
		},
		"components": [
			{"type": "library", "name": "pkg", "version": "v1.0.0", "bom-ref": "ref"}
		],
		"dependencies": [
			{"ref": "ref", "dependsOn": ["other-ref"]}
		]
	}`)

	bom, err := parser.ParseBOM(input)

	require.NoError(t, err)
	require.NotNil(t, bom)
	assert.Equal(t, "CycloneDX", bom.BOMFormat)
	assert.Equal(t, "1.4", bom.SpecVersion)
	assert.Len(t, bom.Components, 1)
	assert.Len(t, bom.Dependencies, 1)
}

func TestParser_ParseBOM_Empty(t *testing.T) {
	parser := NewParser()

	bom, err := parser.ParseBOM([]byte{})

	require.NoError(t, err)
	assert.Nil(t, bom)
}

func TestParser_GetComponentCount(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"components": [
			{"type": "library", "name": "pkg1", "version": "v1", "bom-ref": "r1"},
			{"type": "library", "name": "pkg2", "version": "v2", "bom-ref": "r2"}
		]
	}`)

	count, err := parser.GetComponentCount(input)

	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestParser_GetComponentCount_Empty(t *testing.T) {
	parser := NewParser()

	count, err := parser.GetComponentCount([]byte{})

	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestParser_GetDependencyTree(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"components": [],
		"dependencies": [
			{"ref": "pkg1", "dependsOn": ["pkg2", "pkg3"]},
			{"ref": "pkg2", "dependsOn": ["pkg4"]}
		]
	}`)

	deps, err := parser.GetDependencyTree(input)

	require.NoError(t, err)
	assert.Len(t, deps, 2)
	assert.Equal(t, "pkg1", deps[0].Ref)
	assert.Len(t, deps[0].DependsOn, 2)
}

func TestParser_Parse_WithScope(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"components": [
			{
				"type": "library",
				"name": "test-pkg",
				"version": "v1.0.0",
				"bom-ref": "ref",
				"scope": "required"
			}
		]
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "required", findings[0].Metadata["scope"])
}

func TestParser_GetDependencyTree_Empty(t *testing.T) {
	parser := NewParser()

	deps, err := parser.GetDependencyTree([]byte{})

	require.NoError(t, err)
	assert.Empty(t, deps)
}

func TestParser_GetDependencyTree_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.GetDependencyTree([]byte(`{invalid}`))

	assert.Error(t, err)
}

func TestParser_GetComponentCount_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.GetComponentCount([]byte(`{invalid}`))

	assert.Error(t, err)
}

func TestParser_ParseBOM_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.ParseBOM([]byte(`{invalid}`))

	assert.Error(t, err)
}

func TestParser_Parse_WithMultipleLicenses(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"components": [
			{
				"type": "library",
				"name": "multi-license-pkg",
				"version": "v1.0.0",
				"bom-ref": "ref",
				"licenses": [
					{"license": {"id": "MIT"}},
					{"license": {"id": "Apache-2.0"}}
				]
			}
		]
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	// Should get first license
	assert.Equal(t, "MIT", findings[0].Metadata["license"])
}

func TestParser_Parse_WithExternalReferences(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"components": [
			{
				"type": "library",
				"name": "pkg-with-refs",
				"version": "v1.0.0",
				"bom-ref": "ref",
				"externalReferences": [
					{"type": "website", "url": "https://example.com"},
					{"type": "vcs", "url": "https://github.com/example/pkg"}
				]
			}
		]
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
}

func TestParser_Parse_ComponentWithLicenseName(t *testing.T) {
	parser := NewParser()
	input := []byte(`{
		"components": [
			{
				"type": "library",
				"name": "named-license-pkg",
				"version": "v1.0.0",
				"bom-ref": "ref",
				"licenses": [
					{"license": {"name": "Custom License"}}
				]
			}
		]
	}`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "Custom License", findings[0].Metadata["license"])
}
