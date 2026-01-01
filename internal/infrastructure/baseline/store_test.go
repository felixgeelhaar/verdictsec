package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	domainBaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testStoreReason = "Test baseline reason"

func TestNewStore(t *testing.T) {
	store := NewStore()

	assert.NotNil(t, store)
	assert.Equal(t, ".verdict/baseline.json", store.defaultPath)
}

func TestNewStoreWithPath(t *testing.T) {
	store := NewStoreWithPath("/custom/path/baseline.json")

	assert.NotNil(t, store)
	assert.Equal(t, "/custom/path/baseline.json", store.defaultPath)
}

func TestStore_LoadFromPath_NotFound(t *testing.T) {
	store := NewStore()

	baseline, err := store.LoadFromPath("/nonexistent/baseline.json")

	require.NoError(t, err)
	assert.NotNil(t, baseline)
	assert.Equal(t, 0, baseline.Count())
}

func TestStore_LoadFromPath_ValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	jsonData := []byte(`{
		"version": "1",
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z",
		"fingerprints": [
			{"fingerprint": "abc123", "rule_id": "G101", "engine_id": "gosec", "file": "main.go", "added_at": "2024-01-01T00:00:00Z"},
			{"fingerprint": "def456", "rule_id": "G104", "engine_id": "gosec", "file": "util.go", "added_at": "2024-01-01T00:00:00Z"}
		]
	}`)
	require.NoError(t, os.WriteFile(baselinePath, jsonData, 0644))

	store := NewStore()
	baseline, err := store.LoadFromPath(baselinePath)

	require.NoError(t, err)
	assert.NotNil(t, baseline)
	assert.Equal(t, 2, baseline.Count())
}

func TestStore_LoadFromBytes_Empty(t *testing.T) {
	store := NewStore()

	baseline, err := store.LoadFromBytes([]byte{})

	require.NoError(t, err)
	assert.NotNil(t, baseline)
	assert.Equal(t, 0, baseline.Count())
}

func TestStore_LoadFromBytes_InvalidJSON(t *testing.T) {
	store := NewStore()

	_, err := store.LoadFromBytes([]byte(`{invalid json`))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse baseline file")
}

func TestStore_LoadFromBytes_ValidJSON(t *testing.T) {
	store := NewStore()
	jsonData := []byte(`{
		"version": "1",
		"fingerprints": [
			{"fingerprint": "fp1", "rule_id": "R1", "engine_id": "e1", "file": "a.go"},
			{"fingerprint": "fp2", "rule_id": "R2", "engine_id": "e2", "file": "b.go"}
		]
	}`)

	baseline, err := store.LoadFromBytes(jsonData)

	require.NoError(t, err)
	assert.Equal(t, 2, baseline.Count())
}

func TestStore_SaveToPath(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "subdir", "baseline.json")

	store := NewStore()
	baseline := domainBaseline.NewBaseline("")
	_ = baseline.Add(createTestFinding("G101", "test1.go", 10), testStoreReason)
	_ = baseline.Add(createTestFinding("G104", "test2.go", 20), testStoreReason)

	err := store.SaveToPath(baseline, baselinePath)

	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(baselinePath)
	require.NoError(t, err)

	// Load it back and verify
	loaded, err := store.LoadFromPath(baselinePath)
	require.NoError(t, err)
	assert.Equal(t, 2, loaded.Count())
}

func TestStore_SaveToPathWithMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	store := NewStore()
	baseline := domainBaseline.NewBaseline("")
	_ = baseline.Add(createTestFinding("G101", "meta.go", 10), testStoreReason)

	metadata := BaselineMetadata{
		Description: "Test baseline",
		Project:     "test-project",
		Branch:      "main",
		Engines:     []string{"gosec", "gitleaks"},
		AddedBy:     "test@example.com",
	}

	err := store.SaveToPathWithMetadata(baseline, baselinePath, metadata)

	require.NoError(t, err)

	// Read the raw file to verify metadata
	data, err := os.ReadFile(baselinePath)
	require.NoError(t, err)

	assert.Contains(t, string(data), "test-project")
	assert.Contains(t, string(data), "main")
	assert.Contains(t, string(data), "Test baseline")
	assert.Contains(t, string(data), "test@example.com")
}

func TestStore_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	store := NewStoreWithPath(baselinePath)

	// Initially doesn't exist
	assert.False(t, store.Exists())

	// Create file
	require.NoError(t, os.WriteFile(baselinePath, []byte(`{}`), 0644))

	// Now exists
	assert.True(t, store.Exists())
}

func TestStore_ExistsAt(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.json")

	store := NewStore()

	// Doesn't exist
	assert.False(t, store.ExistsAt(filePath))

	// Create file
	require.NoError(t, os.WriteFile(filePath, []byte(`{}`), 0644))

	// Now exists
	assert.True(t, store.ExistsAt(filePath))

	// Directory should return false
	assert.False(t, store.ExistsAt(tmpDir))
}

func TestStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	// Create file
	require.NoError(t, os.WriteFile(baselinePath, []byte(`{}`), 0644))

	store := NewStoreWithPath(baselinePath)

	// File exists
	assert.True(t, store.Exists())

	// Delete it
	err := store.Delete()
	require.NoError(t, err)

	// No longer exists
	assert.False(t, store.Exists())
}

func TestStore_DeleteAt(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.json")

	// Create file
	require.NoError(t, os.WriteFile(filePath, []byte(`{}`), 0644))

	store := NewStore()

	// Delete it
	err := store.DeleteAt(filePath)
	require.NoError(t, err)

	// No longer exists
	assert.False(t, store.ExistsAt(filePath))
}

func TestStore_DeleteAt_NotFound(t *testing.T) {
	store := NewStore()

	// Delete non-existent file should not error
	err := store.DeleteAt("/nonexistent/file.json")
	require.NoError(t, err)
}

func TestStore_Load_DefaultPath(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)

	os.Chdir(tmpDir)

	store := NewStore()

	// No file, returns empty baseline
	baseline, err := store.Load()
	require.NoError(t, err)
	assert.Equal(t, 0, baseline.Count())
}

func TestStore_Save_DefaultPath(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	store := NewStoreWithPath(baselinePath)
	baseline := domainBaseline.NewBaseline("")
	_ = baseline.Add(createTestFinding("G101", "default.go", 10), testStoreReason)

	err := store.Save(baseline)
	require.NoError(t, err)

	// Verify saved
	loaded, err := store.Load()
	require.NoError(t, err)
	assert.Equal(t, 1, loaded.Count())
}

func TestStore_SaveWithMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	store := NewStoreWithPath(baselinePath)
	baseline := domainBaseline.NewBaseline("")
	_ = baseline.Add(createTestFinding("G101", "meta.go", 10), testStoreReason)

	metadata := BaselineMetadata{
		Description: "With metadata",
		Project:     "my-project",
	}

	err := store.SaveWithMetadata(baseline, metadata)
	require.NoError(t, err)

	// Verify file has metadata
	data, err := os.ReadFile(baselinePath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "With metadata")
	assert.Contains(t, string(data), "my-project")
}

func TestCreateFromFindings(t *testing.T) {
	findings := []*finding.Finding{
		createTestFinding("G101", "main.go", 10),
		createTestFinding("G104", "util.go", 20),
		createTestFinding("G101", "other.go", 30),
	}

	baseline, err := CreateFromFindings(findings, testStoreReason)

	require.NoError(t, err)
	assert.Equal(t, 3, baseline.Count())
}

func TestUpdateFromFindings(t *testing.T) {
	baseline := domainBaseline.NewBaseline("")
	_ = baseline.Add(createTestFinding("G101", "existing.go", 10), testStoreReason)

	newFindings := []*finding.Finding{
		createTestFinding("G104", "new.go", 20),
	}

	result, err := UpdateFromFindings(baseline, newFindings, testStoreReason)

	require.NoError(t, err)
	assert.Equal(t, 2, result.Count())
}

func TestMergeBaselines(t *testing.T) {
	baseline1 := domainBaseline.NewBaseline("")
	_ = baseline1.Add(createTestFinding("G101", "a.go", 10), testStoreReason)
	_ = baseline1.Add(createTestFinding("G102", "b.go", 20), testStoreReason)

	baseline2 := domainBaseline.NewBaseline("")
	_ = baseline2.Add(createTestFinding("G103", "c.go", 30), testStoreReason)

	baseline3 := domainBaseline.NewBaseline("")
	_ = baseline3.Add(createTestFinding("G104", "d.go", 40), testStoreReason)

	result := MergeBaselines(baseline1, baseline2, baseline3)

	assert.Equal(t, 4, result.Count())
}

func TestBaselineFile_Structure(t *testing.T) {
	store := NewStore()
	baseline := domainBaseline.NewBaseline("")
	_ = baseline.Add(createTestFinding("G101", "structure.go", 10), testStoreReason)

	file := store.toBaselineFile(baseline)

	assert.Equal(t, "1", file.Version)
	assert.False(t, file.CreatedAt.IsZero())
	assert.False(t, file.UpdatedAt.IsZero())
	assert.Len(t, file.Fingerprints, 1)
}

func TestBaselineFile_WithMetadata(t *testing.T) {
	store := NewStore()
	baseline := domainBaseline.NewBaseline("")
	_ = baseline.Add(createTestFinding("G101", "metadata.go", 10), testStoreReason)

	metadata := BaselineMetadata{
		Description: "Test description",
		Project:     "test-proj",
		Branch:      "develop",
		Engines:     []string{"gosec", "govulncheck"},
		AddedBy:     "admin@test.com",
	}

	file := store.toBaselineFileWithMetadata(baseline, metadata)

	assert.Equal(t, "Test description", file.Description)
	assert.Equal(t, "test-proj", file.Scope.Project)
	assert.Equal(t, "develop", file.Scope.Branch)
	assert.Equal(t, []string{"gosec", "govulncheck"}, file.Scope.Engines)
	assert.Equal(t, "admin@test.com", file.Fingerprints[0].AddedBy)
}

func TestStore_LoadFromPath_WithScope(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	jsonData := []byte(`{
		"version": "1",
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": "2024-01-01T00:00:00Z",
		"description": "Production baseline",
		"scope": {
			"project": "verdictsec",
			"branch": "main",
			"engines": ["gosec", "gitleaks"]
		},
		"fingerprints": [
			{
				"fingerprint": "scoped-fp",
				"rule_id": "G101",
				"engine_id": "gosec",
				"file": "secret.go",
				"added_at": "2024-01-01T00:00:00Z",
				"reason": "False positive",
				"added_by": "security@example.com"
			}
		]
	}`)
	require.NoError(t, os.WriteFile(baselinePath, jsonData, 0644))

	store := NewStore()
	baseline, err := store.LoadFromPath(baselinePath)

	require.NoError(t, err)
	assert.Equal(t, 1, baseline.Count())
}

func TestStore_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "roundtrip.json")

	// Create baseline with multiple findings
	original := domainBaseline.NewBaseline("")
	_ = original.Add(createTestFinding("G101", "alpha.go", 10), testStoreReason)
	_ = original.Add(createTestFinding("G102", "beta.go", 20), testStoreReason)
	_ = original.Add(createTestFinding("G103", "gamma.go", 30), testStoreReason)

	store := NewStoreWithPath(baselinePath)

	// Save
	err := store.Save(original)
	require.NoError(t, err)

	// Load
	loaded, err := store.Load()
	require.NoError(t, err)

	// Verify count matches
	assert.Equal(t, original.Count(), loaded.Count())
}

func TestFingerprintEntry_Fields(t *testing.T) {
	entry := FingerprintEntry{
		Fingerprint: "test-fingerprint",
		RuleID:      "G101",
		EngineID:    "gosec",
		File:        "test.go",
		AddedAt:     time.Now(),
		Reason:      "False positive",
		AddedBy:     "user@test.com",
	}

	assert.Equal(t, "test-fingerprint", entry.Fingerprint)
	assert.Equal(t, "G101", entry.RuleID)
	assert.Equal(t, "gosec", entry.EngineID)
	assert.Equal(t, "test.go", entry.File)
	assert.Equal(t, "False positive", entry.Reason)
	assert.Equal(t, "user@test.com", entry.AddedBy)
	assert.False(t, entry.AddedAt.IsZero())
}

func TestBaselineScope_Fields(t *testing.T) {
	scope := BaselineScope{
		Project: "test-project",
		Branch:  "feature-branch",
		Engines: []string{"gosec", "gitleaks", "govulncheck"},
	}

	assert.Equal(t, "test-project", scope.Project)
	assert.Equal(t, "feature-branch", scope.Branch)
	assert.Len(t, scope.Engines, 3)
}

func TestStore_DefaultPath(t *testing.T) {
	store := NewStore()
	assert.Equal(t, ".verdict/baseline.json", store.DefaultPath())

	customStore := NewStoreWithPath("/custom/path.json")
	assert.Equal(t, "/custom/path.json", customStore.DefaultPath())
}

func TestStore_LoadFrom(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	jsonData := []byte(`{
		"version": "1",
		"fingerprints": [
			{"fingerprint": "fp1", "rule_id": "R1", "engine_id": "e1", "file": "a.go"}
		]
	}`)
	require.NoError(t, os.WriteFile(baselinePath, jsonData, 0644))

	store := NewStore()
	baseline, err := store.LoadFrom(baselinePath)

	require.NoError(t, err)
	assert.Equal(t, 1, baseline.Count())
}

func TestStore_SaveTo(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "saveto.json")

	store := NewStore()
	baseline := domainBaseline.NewBaseline("")
	_ = baseline.Add(createTestFinding("G101", "saveto.go", 10), testStoreReason)

	err := store.SaveTo(baseline, baselinePath)
	require.NoError(t, err)

	// Verify file was created
	assert.True(t, store.ExistsAt(baselinePath))

	// Load it back
	loaded, err := store.LoadFrom(baselinePath)
	require.NoError(t, err)
	assert.Equal(t, 1, loaded.Count())
}

func TestCreateFromFindings_EmptyReason(t *testing.T) {
	findings := []*finding.Finding{
		createTestFinding("G101", "main.go", 10),
	}

	_, err := CreateFromFindings(findings, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "reason is required")
}

func TestUpdateFromFindings_EmptyReason(t *testing.T) {
	baseline := domainBaseline.NewBaseline("")
	_ = baseline.Add(createTestFinding("G101", "existing.go", 10), testStoreReason)

	newFindings := []*finding.Finding{
		createTestFinding("G104", "new.go", 20),
	}

	_, err := UpdateFromFindings(baseline, newFindings, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "reason is required")
}

func TestStore_LoadFromPath_InvalidPath(t *testing.T) {
	store := NewStore()

	// Path with null bytes should fail validation
	_, err := store.LoadFromPath("invalid\x00path")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid baseline path")
}

// Helper to create a test finding
func createTestFinding(ruleID, file string, line int) *finding.Finding {
	loc := finding.NewLocation(file, line, 1, line, 80)
	return finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		ruleID,
		"Test finding",
		finding.SeverityMedium,
		loc,
	)
}
