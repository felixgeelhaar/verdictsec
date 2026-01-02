package services

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestComponent(name, version string) sbom.Component {
	return sbom.NewComponentFull(name, version, "pkg:golang/"+name+"@"+version, "MIT", "go", "library")
}

func TestNewSBOMDiffService(t *testing.T) {
	svc := NewSBOMDiffService()
	assert.NotNil(t, svc)
}

func TestSBOMDiffService_Diff_NilSBOMs(t *testing.T) {
	svc := NewSBOMDiffService()

	result := svc.Diff(nil, nil)

	assert.Nil(t, result.Base)
	assert.Nil(t, result.Target)
	assert.Empty(t, result.Added)
	assert.Empty(t, result.Removed)
	assert.Empty(t, result.Modified)
	assert.Empty(t, result.Unchanged)
	assert.False(t, result.HasChanges())
}

func TestSBOMDiffService_Diff_NilBase(t *testing.T) {
	svc := NewSBOMDiffService()

	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
		createTestComponent("pkg2", "v2.0.0"),
	})

	result := svc.Diff(nil, target)

	assert.Nil(t, result.Base)
	assert.NotNil(t, result.Target)
	assert.Len(t, result.Added, 2)
	assert.Empty(t, result.Removed)
	assert.Empty(t, result.Modified)
	assert.True(t, result.HasChanges())
}

func TestSBOMDiffService_Diff_NilTarget(t *testing.T) {
	svc := NewSBOMDiffService()

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
		createTestComponent("pkg2", "v2.0.0"),
	})

	result := svc.Diff(base, nil)

	assert.NotNil(t, result.Base)
	assert.Nil(t, result.Target)
	assert.Empty(t, result.Added)
	assert.Len(t, result.Removed, 2)
	assert.Empty(t, result.Modified)
	assert.True(t, result.HasChanges())
}

func TestSBOMDiffService_Diff_NoChanges(t *testing.T) {
	svc := NewSBOMDiffService()

	components := []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
		createTestComponent("pkg2", "v2.0.0"),
	}

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", components)
	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", components)

	result := svc.Diff(base, target)

	assert.Empty(t, result.Added)
	assert.Empty(t, result.Removed)
	assert.Empty(t, result.Modified)
	assert.Len(t, result.Unchanged, 2)
	assert.False(t, result.HasChanges())
}

func TestSBOMDiffService_Diff_AddedComponents(t *testing.T) {
	svc := NewSBOMDiffService()

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
	})

	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
		createTestComponent("pkg2", "v2.0.0"),
		createTestComponent("pkg3", "v3.0.0"),
	})

	result := svc.Diff(base, target)

	assert.Len(t, result.Added, 2)
	assert.Empty(t, result.Removed)
	assert.Empty(t, result.Modified)
	assert.Len(t, result.Unchanged, 1)
	assert.True(t, result.HasChanges())
}

func TestSBOMDiffService_Diff_RemovedComponents(t *testing.T) {
	svc := NewSBOMDiffService()

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
		createTestComponent("pkg2", "v2.0.0"),
		createTestComponent("pkg3", "v3.0.0"),
	})

	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
	})

	result := svc.Diff(base, target)

	assert.Empty(t, result.Added)
	assert.Len(t, result.Removed, 2)
	assert.Empty(t, result.Modified)
	assert.Len(t, result.Unchanged, 1)
	assert.True(t, result.HasChanges())
}

func TestSBOMDiffService_Diff_ModifiedVersion(t *testing.T) {
	svc := NewSBOMDiffService()

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
		createTestComponent("pkg2", "v2.0.0"),
	})

	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
		createTestComponent("pkg2", "v3.0.0"), // Major version bump
	})

	result := svc.Diff(base, target)

	assert.Empty(t, result.Added)
	assert.Empty(t, result.Removed)
	require.Len(t, result.Modified, 1)
	assert.Len(t, result.Unchanged, 1)
	assert.True(t, result.HasChanges())

	mod := result.Modified[0]
	assert.Equal(t, "pkg2", mod.Target.Name())
	assert.Equal(t, "v2.0.0", mod.Base.Version())
	assert.Equal(t, "v3.0.0", mod.Target.Version())
	assert.Equal(t, sbom.VersionMajor, mod.VersionChange)
	assert.False(t, mod.LicenseChange)
}

func TestSBOMDiffService_Diff_ModifiedLicense(t *testing.T) {
	svc := NewSBOMDiffService()

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		sbom.NewComponentFull("pkg1", "v1.0.0", "pkg:golang/pkg1@v1.0.0", "MIT", "go", "library"),
	})

	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		sbom.NewComponentFull("pkg1", "v1.0.1", "pkg:golang/pkg1@v1.0.1", "Apache-2.0", "go", "library"),
	})

	result := svc.Diff(base, target)

	require.Len(t, result.Modified, 1)
	mod := result.Modified[0]
	assert.Equal(t, sbom.VersionPatch, mod.VersionChange)
	assert.True(t, mod.LicenseChange)
}

func TestSBOMDiffService_Diff_MixedChanges(t *testing.T) {
	svc := NewSBOMDiffService()

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("unchanged", "v1.0.0"),
		createTestComponent("removed", "v1.0.0"),
		createTestComponent("modified", "v1.0.0"),
	})

	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("unchanged", "v1.0.0"),
		createTestComponent("added", "v1.0.0"),
		createTestComponent("modified", "v1.1.0"),
	})

	result := svc.Diff(base, target)

	assert.Len(t, result.Added, 1)
	assert.Len(t, result.Removed, 1)
	assert.Len(t, result.Modified, 1)
	assert.Len(t, result.Unchanged, 1)
	assert.True(t, result.HasChanges())

	// Verify specific changes
	assert.Equal(t, "added", result.Added[0].Name())
	assert.Equal(t, "removed", result.Removed[0].Name())
	assert.Equal(t, "modified", result.Modified[0].Target.Name())
}

func TestSBOMDiffResult_Stats(t *testing.T) {
	svc := NewSBOMDiffService()

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("unchanged", "v1.0.0"),
		createTestComponent("removed", "v1.0.0"),
		createTestComponent("mod-major", "v1.0.0"),
		createTestComponent("mod-minor", "v1.0.0"),
		createTestComponent("mod-patch", "v1.0.0"),
	})

	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("unchanged", "v1.0.0"),
		createTestComponent("added", "v1.0.0"),
		createTestComponent("mod-major", "v2.0.0"),
		createTestComponent("mod-minor", "v1.1.0"),
		createTestComponent("mod-patch", "v1.0.1"),
	})

	result := svc.Diff(base, target)
	stats := result.Stats()

	assert.Equal(t, 1, stats.AddedCount)
	assert.Equal(t, 1, stats.RemovedCount)
	assert.Equal(t, 3, stats.ModifiedCount)
	assert.Equal(t, 1, stats.UnchangedCount)
	assert.Equal(t, 1, stats.MajorChanges)
	assert.Equal(t, 1, stats.MinorChanges)
	assert.Equal(t, 1, stats.PatchChanges)
	assert.Equal(t, 0, stats.LicenseChanges)
}

func TestSBOMDiffResult_TotalBase(t *testing.T) {
	svc := NewSBOMDiffService()

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
		createTestComponent("pkg2", "v2.0.0"),
	})

	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		createTestComponent("pkg1", "v1.0.0"),
	})

	result := svc.Diff(base, target)

	assert.Equal(t, 2, result.TotalBase())
	assert.Equal(t, 1, result.TotalTarget())
}

func TestSBOMDiffResult_TotalBase_NilSBOM(t *testing.T) {
	result := SBOMDiffResult{Base: nil, Target: nil}

	assert.Equal(t, 0, result.TotalBase())
	assert.Equal(t, 0, result.TotalTarget())
}

func TestSBOMDiffService_MatchByName(t *testing.T) {
	// Test matching when PURL is not available (match by name)
	svc := NewSBOMDiffService()

	base := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		sbom.NewComponent("pkg1", "v1.0.0", ""), // No PURL
	})

	target := sbom.NewSBOM(sbom.FormatCycloneDX, "app", []sbom.Component{
		sbom.NewComponent("pkg1", "v2.0.0", ""), // No PURL, same name
	})

	result := svc.Diff(base, target)

	assert.Empty(t, result.Added)
	assert.Empty(t, result.Removed)
	require.Len(t, result.Modified, 1)
	assert.Equal(t, sbom.VersionMajor, result.Modified[0].VersionChange)
}
