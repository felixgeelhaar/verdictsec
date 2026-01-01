package syft

import (
	"encoding/json"
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

	assert.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParser_Parse_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.Parse([]byte("not json"))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal syft output")
}

func TestParser_Parse_ValidOutput(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		Artifacts: []Artifact{
			{
				ID:       "pkg-1",
				Name:     "github.com/example/pkg",
				Version:  "v1.2.3",
				Type:     "go-module",
				FoundBy:  "go-mod-file-cataloger",
				Language: "go",
				PURL:     "pkg:golang/github.com/example/pkg@v1.2.3",
				Locations: []Location{
					{Path: "go.mod"},
				},
				Licenses: []License{
					{Value: "MIT", SPDXExpression: "MIT"},
				},
				CPEs: []string{"cpe:2.3:a:example:pkg:1.2.3:*:*:*:*:*:*:*"},
			},
		},
		Source: Source{
			ID:   "source-1",
			Name: "test-project",
			Type: "directory",
		},
		Descriptor: Descriptor{
			Name:    "syft",
			Version: "0.98.0",
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	findings, err := parser.Parse(data)

	assert.NoError(t, err)
	assert.Len(t, findings, 1)

	finding := findings[0]
	assert.Equal(t, "sbom-artifact", finding.RuleID)
	assert.Contains(t, finding.Message, "github.com/example/pkg@v1.2.3")
	assert.Contains(t, finding.Message, "go-module")
	assert.Equal(t, "INFO", finding.Severity)
	assert.Equal(t, "HIGH", finding.Confidence)
	assert.Equal(t, "go.mod", finding.File)

	// Check metadata
	assert.Equal(t, "go-module", finding.Metadata["artifact_type"])
	assert.Equal(t, "pkg-1", finding.Metadata["artifact_id"])
	assert.Equal(t, "go-mod-file-cataloger", finding.Metadata["found_by"])
	assert.Equal(t, "go", finding.Metadata["language"])
	assert.Equal(t, "pkg:golang/github.com/example/pkg@v1.2.3", finding.Metadata["purl"])
	assert.Equal(t, "MIT", finding.Metadata["license"])
	assert.Equal(t, "directory", finding.Metadata["source_type"])
	assert.Equal(t, "test-project", finding.Metadata["source_name"])
}

func TestParser_Parse_MultipleArtifacts(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		Artifacts: []Artifact{
			{ID: "pkg-1", Name: "pkg-a", Version: "1.0.0", Type: "go-module"},
			{ID: "pkg-2", Name: "pkg-b", Version: "2.0.0", Type: "npm"},
			{ID: "pkg-3", Name: "pkg-c", Version: "3.0.0", Type: "python"},
		},
		Source: Source{Type: "directory", Name: "test"},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	findings, err := parser.Parse(data)

	assert.NoError(t, err)
	assert.Len(t, findings, 3)
}

func TestParser_Parse_ContainerImage(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		Artifacts: []Artifact{
			{
				ID:      "pkg-1",
				Name:    "libssl",
				Version: "1.1.1",
				Type:    "deb",
				Locations: []Location{
					{Path: "/usr/lib/libssl.so", LayerID: "sha256:abc123"},
				},
			},
		},
		Source: Source{
			ID:   "source-1",
			Name: "nginx:latest",
			Type: "image",
			Metadata: SourceMeta{
				ImageID:        "sha256:xyz789",
				ManifestDigest: "sha256:manifest123",
				Architecture:   "amd64",
				OS:             "linux",
			},
		},
		Distro: &Distro{
			Name:    "debian",
			ID:      "debian",
			Version: "11",
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	findings, err := parser.Parse(data)

	assert.NoError(t, err)
	assert.Len(t, findings, 1)

	finding := findings[0]
	assert.Equal(t, "/usr/lib/libssl.so", finding.File)
	assert.Equal(t, "sha256:abc123", finding.Metadata["layer_id"])
	assert.Equal(t, "image", finding.Metadata["source_type"])
	assert.Equal(t, "nginx:latest", finding.Metadata["source_name"])
}

func TestParser_ParseOutput(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		Artifacts: []Artifact{
			{ID: "pkg-1", Name: "test", Version: "1.0.0"},
		},
		Source: Source{Type: "directory", Name: "test"},
		Descriptor: Descriptor{
			Name:    "syft",
			Version: "0.98.0",
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	parsed, err := parser.ParseOutput(data)

	assert.NoError(t, err)
	assert.NotNil(t, parsed)
	assert.Len(t, parsed.Artifacts, 1)
	assert.Equal(t, "syft", parsed.Descriptor.Name)
}

func TestParser_ParseOutput_Empty(t *testing.T) {
	parser := NewParser()

	parsed, err := parser.ParseOutput([]byte{})

	assert.NoError(t, err)
	assert.Nil(t, parsed)
}

func TestParser_GetArtifactCount(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		Artifacts: []Artifact{
			{ID: "pkg-1", Name: "a"},
			{ID: "pkg-2", Name: "b"},
			{ID: "pkg-3", Name: "c"},
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	count, err := parser.GetArtifactCount(data)

	assert.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestParser_GetArtifactCount_Empty(t *testing.T) {
	parser := NewParser()

	count, err := parser.GetArtifactCount([]byte{})

	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestParser_GetSourceInfo(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		Source: Source{
			ID:      "source-1",
			Name:    "my-app",
			Version: "1.0.0",
			Type:    "directory",
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	source, err := parser.GetSourceInfo(data)

	assert.NoError(t, err)
	assert.NotNil(t, source)
	assert.Equal(t, "my-app", source.Name)
	assert.Equal(t, "directory", source.Type)
}

func TestParser_GetSourceInfo_Empty(t *testing.T) {
	parser := NewParser()

	source, err := parser.GetSourceInfo([]byte{})

	assert.NoError(t, err)
	assert.Nil(t, source)
}

func TestParser_GetRelationships(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		ArtifactRelationships: []Relation{
			{Parent: "pkg-1", Child: "pkg-2", Type: "contains"},
			{Parent: "pkg-2", Child: "pkg-3", Type: "depends-on"},
		},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	relations, err := parser.GetRelationships(data)

	assert.NoError(t, err)
	assert.Len(t, relations, 2)
	assert.Equal(t, "pkg-1", relations[0].Parent)
	assert.Equal(t, "pkg-2", relations[0].Child)
	assert.Equal(t, "contains", relations[0].Type)
}

func TestParser_GetRelationships_Empty(t *testing.T) {
	parser := NewParser()

	relations, err := parser.GetRelationships([]byte{})

	assert.NoError(t, err)
	assert.Nil(t, relations)
}

func TestParser_Parse_WithCPE(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		Artifacts: []Artifact{
			{
				ID:      "pkg-1",
				Name:    "openssl",
				Version: "1.1.1",
				Type:    "deb",
				CPEs:    []string{"cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"},
			},
		},
		Source: Source{Type: "image"},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	findings, err := parser.Parse(data)

	assert.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*", findings[0].Metadata["cpe"])
}

func TestParser_Parse_NoLicense(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		Artifacts: []Artifact{
			{
				ID:       "pkg-1",
				Name:     "unknown-pkg",
				Version:  "1.0.0",
				Type:     "go-module",
				Licenses: nil,
			},
		},
		Source: Source{Type: "directory"},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	findings, err := parser.Parse(data)

	assert.NoError(t, err)
	assert.Len(t, findings, 1)
	_, hasLicense := findings[0].Metadata["license"]
	assert.False(t, hasLicense)
}

func TestParser_Parse_LicenseWithValueOnly(t *testing.T) {
	parser := NewParser()

	output := SyftOutput{
		Artifacts: []Artifact{
			{
				ID:      "pkg-1",
				Name:    "some-pkg",
				Version: "1.0.0",
				Type:    "npm",
				Licenses: []License{
					{Value: "Apache-2.0"},
				},
			},
		},
		Source: Source{Type: "directory"},
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	findings, err := parser.Parse(data)

	assert.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "Apache-2.0", findings[0].Metadata["license"])
}
