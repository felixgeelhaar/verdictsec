package sbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	domainsbom "github.com/felixgeelhaar/verdictsec/internal/domain/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cycloneDXSample = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:test-uuid",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "tools": [
      {
        "vendor": "CycloneDX",
        "name": "cyclonedx-gomod",
        "version": "1.4.0"
      }
    ],
    "component": {
      "type": "application",
      "bom-ref": "pkg:golang/github.com/example/app@v1.0.0",
      "name": "github.com/example/app",
      "version": "v1.0.0",
      "purl": "pkg:golang/github.com/example/app@v1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:golang/github.com/example/pkg1@v1.2.3",
      "name": "github.com/example/pkg1",
      "version": "v1.2.3",
      "purl": "pkg:golang/github.com/example/pkg1@v1.2.3",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "pkg:golang/github.com/other/pkg2@v2.0.0",
      "name": "github.com/other/pkg2",
      "version": "v2.0.0",
      "purl": "pkg:golang/github.com/other/pkg2@v2.0.0",
      "licenses": [
        {
          "license": {
            "name": "Apache-2.0"
          }
        }
      ]
    }
  ]
}`

const syftSample = `{
  "artifacts": [
    {
      "id": "abc123",
      "name": "github.com/example/pkg1",
      "version": "v1.2.3",
      "type": "go-module",
      "foundBy": "go-mod-file-cataloger",
      "locations": [
        {
          "path": "/go.mod"
        }
      ],
      "licenses": [
        {
          "value": "MIT",
          "spdxExpression": "MIT",
          "type": "declared"
        }
      ],
      "language": "go",
      "cpes": [],
      "purl": "pkg:golang/github.com/example/pkg1@v1.2.3"
    },
    {
      "id": "def456",
      "name": "github.com/other/pkg2",
      "version": "v2.0.0",
      "type": "go-module",
      "foundBy": "go-mod-file-cataloger",
      "locations": [
        {
          "path": "/go.mod"
        }
      ],
      "licenses": [],
      "language": "go",
      "cpes": [],
      "purl": "pkg:golang/github.com/other/pkg2@v2.0.0"
    }
  ],
  "artifactRelationships": [],
  "source": {
    "id": "source-id",
    "type": "directory",
    "target": "/app",
    "name": "/app"
  },
  "distro": {},
  "descriptor": {
    "name": "syft",
    "version": "1.0.0",
    "configuration": {}
  },
  "schema": {
    "version": "16.0.0",
    "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.0.json"
  }
}`

func TestNewLoader(t *testing.T) {
	loader := NewLoader()
	assert.NotNil(t, loader)
}

func TestLoader_LoadFromBytes_CycloneDX(t *testing.T) {
	loader := NewLoader()
	ctx := context.Background()

	sbom, err := loader.LoadFromBytes(ctx, []byte(cycloneDXSample), domainsbom.FormatCycloneDX)

	require.NoError(t, err)
	require.NotNil(t, sbom)
	assert.Equal(t, domainsbom.FormatCycloneDX, sbom.Format())
	assert.Equal(t, "github.com/example/app", sbom.Source())
	assert.Equal(t, 2, sbom.ComponentCount())
	assert.Equal(t, "cyclonedx-gomod", sbom.ToolName())
	assert.Equal(t, "1.4.0", sbom.ToolVersion())

	components := sbom.Components()
	assert.Equal(t, "github.com/example/pkg1", components[0].Name())
	assert.Equal(t, "v1.2.3", components[0].Version())
	assert.Equal(t, "MIT", components[0].License())

	assert.Equal(t, "github.com/other/pkg2", components[1].Name())
	assert.Equal(t, "Apache-2.0", components[1].License())
}

func TestLoader_LoadFromBytes_Syft(t *testing.T) {
	loader := NewLoader()
	ctx := context.Background()

	sbom, err := loader.LoadFromBytes(ctx, []byte(syftSample), domainsbom.FormatSyft)

	require.NoError(t, err)
	require.NotNil(t, sbom)
	assert.Equal(t, domainsbom.FormatSyft, sbom.Format())
	assert.Equal(t, "/app", sbom.Source())
	assert.Equal(t, "directory", sbom.SourceType())
	assert.Equal(t, 2, sbom.ComponentCount())
	assert.Equal(t, "syft", sbom.ToolName())
	assert.Equal(t, "1.0.0", sbom.ToolVersion())

	components := sbom.Components()
	assert.Equal(t, "github.com/example/pkg1", components[0].Name())
	assert.Equal(t, "v1.2.3", components[0].Version())
	assert.Equal(t, "MIT", components[0].License())
	assert.Equal(t, "go", components[0].Language())
}

func TestLoader_LoadFromBytes_AutoDetect(t *testing.T) {
	loader := NewLoader()
	ctx := context.Background()

	tests := []struct {
		name     string
		data     string
		expected domainsbom.Format
	}{
		{
			name:     "detect CycloneDX",
			data:     cycloneDXSample,
			expected: domainsbom.FormatCycloneDX,
		},
		{
			name:     "detect Syft",
			data:     syftSample,
			expected: domainsbom.FormatSyft,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom, err := loader.LoadFromBytes(ctx, []byte(tt.data), domainsbom.FormatUnknown)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, sbom.Format())
		})
	}
}

func TestLoader_LoadFromBytes_InvalidJSON(t *testing.T) {
	loader := NewLoader()
	ctx := context.Background()

	_, err := loader.LoadFromBytes(ctx, []byte("not json"), domainsbom.FormatCycloneDX)
	assert.Error(t, err)
}

func TestLoader_LoadFromBytes_UnknownFormat(t *testing.T) {
	loader := NewLoader()
	ctx := context.Background()

	_, err := loader.LoadFromBytes(ctx, []byte(`{"foo": "bar"}`), domainsbom.FormatUnknown)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to detect SBOM format")
}

func TestLoader_LoadFromFile(t *testing.T) {
	loader := NewLoader()
	ctx := context.Background()

	// Create temp file with CycloneDX content
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sbom.json")
	err := os.WriteFile(filePath, []byte(cycloneDXSample), 0644)
	require.NoError(t, err)

	sbom, err := loader.LoadFromFile(ctx, filePath)
	require.NoError(t, err)
	assert.Equal(t, domainsbom.FormatCycloneDX, sbom.Format())
	assert.Equal(t, 2, sbom.ComponentCount())
}

func TestLoader_LoadFromFile_NotExists(t *testing.T) {
	loader := NewLoader()
	ctx := context.Background()

	_, err := loader.LoadFromFile(ctx, "/nonexistent/path/sbom.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read file")
}

func TestLoader_LoadFromFile_UnknownFormat(t *testing.T) {
	loader := NewLoader()
	ctx := context.Background()

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "unknown.json")
	err := os.WriteFile(filePath, []byte(`{"unknown": "format"}`), 0644)
	require.NoError(t, err)

	_, err = loader.LoadFromFile(ctx, filePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown SBOM format")
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected domainsbom.Format
	}{
		{
			name:     "CycloneDX",
			data:     `{"bomFormat": "CycloneDX"}`,
			expected: domainsbom.FormatCycloneDX,
		},
		{
			name:     "CycloneDX case insensitive",
			data:     `{"bomFormat": "cyclonedx"}`,
			expected: domainsbom.FormatCycloneDX,
		},
		{
			name:     "Syft with descriptor",
			data:     `{"artifacts": [], "descriptor": {"name": "syft"}}`,
			expected: domainsbom.FormatSyft,
		},
		{
			name:     "Syft without descriptor",
			data:     `{"artifacts": []}`,
			expected: domainsbom.FormatSyft,
		},
		{
			name:     "SPDX",
			data:     `{"spdxVersion": "SPDX-2.3"}`,
			expected: domainsbom.FormatSPDX,
		},
		{
			name:     "Unknown",
			data:     `{"foo": "bar"}`,
			expected: domainsbom.FormatUnknown,
		},
		{
			name:     "Invalid JSON",
			data:     "not json",
			expected: domainsbom.FormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectFormat([]byte(tt.data))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoader_EmptySBOM(t *testing.T) {
	loader := NewLoader()
	ctx := context.Background()

	emptyCycloneDX := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"metadata": {},
		"components": []
	}`

	sbom, err := loader.LoadFromBytes(ctx, []byte(emptyCycloneDX), domainsbom.FormatCycloneDX)
	require.NoError(t, err)
	assert.Equal(t, 0, sbom.ComponentCount())
}
