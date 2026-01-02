package sbom

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewComponent(t *testing.T) {
	c := NewComponent("github.com/example/pkg", "v1.2.3", "pkg:golang/github.com/example/pkg@v1.2.3")

	assert.Equal(t, "github.com/example/pkg", c.Name())
	assert.Equal(t, "v1.2.3", c.Version())
	assert.Equal(t, "pkg:golang/github.com/example/pkg@v1.2.3", c.PURL())
	assert.Empty(t, c.License())
}

func TestNewComponentFull(t *testing.T) {
	c := NewComponentFull(
		"github.com/example/pkg",
		"v1.2.3",
		"pkg:golang/github.com/example/pkg@v1.2.3",
		"MIT",
		"go",
		"library",
	)

	assert.Equal(t, "github.com/example/pkg", c.Name())
	assert.Equal(t, "v1.2.3", c.Version())
	assert.Equal(t, "pkg:golang/github.com/example/pkg@v1.2.3", c.PURL())
	assert.Equal(t, "MIT", c.License())
	assert.Equal(t, "go", c.Language())
	assert.Equal(t, "library", c.Type())
}

func TestComponent_Key(t *testing.T) {
	tests := []struct {
		name     string
		purl     string
		compName string
		expected string
	}{
		{
			name:     "with PURL",
			purl:     "pkg:golang/github.com/example/pkg@v1.2.3",
			compName: "github.com/example/pkg",
			expected: "pkg:golang/github.com/example/pkg@v1.2.3",
		},
		{
			name:     "without PURL",
			purl:     "",
			compName: "github.com/example/pkg",
			expected: "github.com/example/pkg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewComponentFull(tt.compName, "v1.2.3", tt.purl, "", "", "")
			assert.Equal(t, tt.expected, c.Key())
		})
	}
}

func TestComponent_String(t *testing.T) {
	c := NewComponent("github.com/example/pkg", "v1.2.3", "")
	assert.Equal(t, "github.com/example/pkg@v1.2.3", c.String())
}

func TestCompareVersion(t *testing.T) {
	tests := []struct {
		name     string
		oldVer   string
		newVer   string
		expected VersionChange
	}{
		{
			name:     "major upgrade",
			oldVer:   "v1.2.3",
			newVer:   "v2.0.0",
			expected: VersionMajor,
		},
		{
			name:     "minor upgrade",
			oldVer:   "v1.2.3",
			newVer:   "v1.3.0",
			expected: VersionMinor,
		},
		{
			name:     "patch upgrade",
			oldVer:   "v1.2.3",
			newVer:   "v1.2.4",
			expected: VersionPatch,
		},
		{
			name:     "same version",
			oldVer:   "v1.2.3",
			newVer:   "v1.2.3",
			expected: VersionUnchanged,
		},
		{
			name:     "without v prefix",
			oldVer:   "1.2.3",
			newVer:   "2.0.0",
			expected: VersionMajor,
		},
		{
			name:     "non-semver treated as major",
			oldVer:   "abc",
			newVer:   "def",
			expected: VersionMajor, // Different first parts = major
		},
		{
			name:     "prerelease treated as patch",
			oldVer:   "v1.2.3-alpha",
			newVer:   "v1.2.3-beta",
			expected: VersionPatch, // Same major/minor, different patch part (includes prerelease suffix)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareVersion(tt.oldVer, tt.newVer)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewSBOM(t *testing.T) {
	s := NewSBOM(FormatCycloneDX, "myapp", []Component{
		NewComponent("pkg1", "v1.0.0", ""),
		NewComponent("pkg2", "v2.0.0", ""),
	})

	assert.Equal(t, FormatCycloneDX, s.Format())
	assert.Equal(t, "myapp", s.Source())
	assert.Equal(t, 2, s.ComponentCount())
	assert.NotZero(t, s.Timestamp())
}

func TestNewSBOMFull(t *testing.T) {
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	s := NewSBOMFull(
		FormatSyft,
		"myapp",
		"directory",
		[]Component{NewComponent("pkg1", "v1.0.0", "")},
		ts,
		"syft",
		"1.0.0",
	)

	assert.Equal(t, FormatSyft, s.Format())
	assert.Equal(t, "myapp", s.Source())
	assert.Equal(t, "directory", s.SourceType())
	assert.Equal(t, 1, s.ComponentCount())
	assert.Equal(t, ts, s.Timestamp())
	assert.Equal(t, "syft", s.ToolName())
	assert.Equal(t, "1.0.0", s.ToolVersion())
}

func TestSBOM_ComponentMap(t *testing.T) {
	c1 := NewComponentFull("pkg1", "v1.0.0", "pkg:golang/pkg1@v1.0.0", "", "", "")
	c2 := NewComponent("pkg2", "v2.0.0", "")

	s := NewSBOM(FormatCycloneDX, "myapp", []Component{c1, c2})
	m := s.ComponentMap()

	require.Len(t, m, 2)
	// ComponentMap uses KeyWithoutVersion() for matching
	assert.Equal(t, "v1.0.0", m["pkg:golang/pkg1"].Version())
	assert.Equal(t, "v2.0.0", m["pkg2"].Version())
}

func TestSBOM_Components(t *testing.T) {
	components := []Component{
		NewComponent("pkg1", "v1.0.0", ""),
		NewComponent("pkg2", "v2.0.0", ""),
	}

	s := NewSBOM(FormatCycloneDX, "myapp", components)
	result := s.Components()

	assert.Len(t, result, 2)
	assert.Equal(t, "pkg1", result[0].Name())
	assert.Equal(t, "v1.0.0", result[0].Version())
	assert.Equal(t, "pkg2", result[1].Name())
	assert.Equal(t, "v2.0.0", result[1].Version())
}

func TestFormat_String(t *testing.T) {
	assert.Equal(t, "cyclonedx", FormatCycloneDX.String())
	assert.Equal(t, "syft", FormatSyft.String())
	assert.Equal(t, "spdx", FormatSPDX.String())
	assert.Equal(t, "unknown", FormatUnknown.String())
}
