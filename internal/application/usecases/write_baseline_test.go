package usecases

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

// mockBaselineStore is a test implementation of ports.BaselineStore
type mockBaselineStore struct {
	baseline    *baseline.Baseline
	savedPath   string
	defaultPath string
	exists      bool
	shouldFail  bool
}

func newMockBaselineStore() *mockBaselineStore {
	return &mockBaselineStore{
		defaultPath: ".verdict/baseline.json",
		exists:      false,
	}
}

func (m *mockBaselineStore) Load() (*baseline.Baseline, error) {
	return m.baseline, nil
}

func (m *mockBaselineStore) LoadFrom(path string) (*baseline.Baseline, error) {
	return m.baseline, nil
}

func (m *mockBaselineStore) Save(b *baseline.Baseline) error {
	if m.shouldFail {
		return assert.AnError
	}
	m.baseline = b
	m.savedPath = m.defaultPath
	return nil
}

func (m *mockBaselineStore) SaveTo(b *baseline.Baseline, path string) error {
	if m.shouldFail {
		return assert.AnError
	}
	m.baseline = b
	m.savedPath = path
	return nil
}

func (m *mockBaselineStore) Exists() bool {
	return m.exists
}

func (m *mockBaselineStore) DefaultPath() string {
	return m.defaultPath
}

func createBaselineFinding(ruleID string, line int) *finding.Finding {
	loc := finding.NewLocation("main.go", line, 1, line, 20)
	return finding.NewFinding(finding.FindingTypeSAST, "gosec", ruleID, "Test", finding.SeverityHigh, loc)
}

const testBaselineReason = "Test baseline reason"

func TestNewWriteBaselineUseCase(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)
	assert.NotNil(t, uc)
}

func TestWriteBaselineUseCase_Write(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	a := assessment.NewAssessment("/test")
	a.AddFinding(createBaselineFinding("G401", 10))
	a.AddFinding(createBaselineFinding("G402", 20))

	output, err := uc.Write(WriteBaselineInput{
		Assessment: a,
		Target:     "/test",
		Reason:     testBaselineReason,
	})

	assert.NoError(t, err)
	assert.Equal(t, 2, output.EntriesAdded)
	assert.NotNil(t, output.Baseline)
	assert.Equal(t, ".verdict/baseline.json", output.Path)
}

func TestWriteBaselineUseCase_Write_RequiresReason(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	a := assessment.NewAssessment("/test")
	a.AddFinding(createBaselineFinding("G401", 10))

	_, err := uc.Write(WriteBaselineInput{
		Assessment: a,
		Target:     "/test",
		Reason:     "", // Empty reason should fail
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason is required")
}

func TestWriteBaselineUseCase_Write_CustomPath(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	a := assessment.NewAssessment("/test")
	a.AddFinding(createBaselineFinding("G401", 10))

	output, err := uc.Write(WriteBaselineInput{
		Assessment: a,
		Target:     "/test",
		Path:       "/custom/baseline.json",
		Reason:     testBaselineReason,
	})

	assert.NoError(t, err)
	assert.Equal(t, "/custom/baseline.json", output.Path)
}

func TestWriteBaselineUseCase_Write_SaveError(t *testing.T) {
	store := newMockBaselineStore()
	store.shouldFail = true
	uc := NewWriteBaselineUseCase(store, nil)

	a := assessment.NewAssessment("/test")

	_, err := uc.Write(WriteBaselineInput{
		Assessment: a,
		Target:     "/test",
		Reason:     testBaselineReason,
	})

	assert.Error(t, err)
}

func TestWriteBaselineUseCase_Update(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	// Existing baseline with one finding
	existingBaseline := baseline.NewBaseline("/test")
	existingFinding := createBaselineFinding("G401", 10)
	_ = existingBaseline.Add(existingFinding, testBaselineReason)

	// Assessment with existing + new finding
	a := assessment.NewAssessment("/test")
	a.AddFinding(existingFinding)
	a.AddFinding(createBaselineFinding("G402", 20))

	output, err := uc.Update(UpdateBaselineInput{
		Assessment: a,
		Baseline:   existingBaseline,
		Reason:     testBaselineReason,
	})

	assert.NoError(t, err)
	assert.Equal(t, 1, output.EntriesAdded)
	assert.Equal(t, 1, output.EntriesUpdated)
	assert.Equal(t, 2, output.Baseline.Count())
}

func TestWriteBaselineUseCase_Update_RequiresReason(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	existingBaseline := baseline.NewBaseline("/test")
	a := assessment.NewAssessment("/test")
	a.AddFinding(createBaselineFinding("G401", 10))

	_, err := uc.Update(UpdateBaselineInput{
		Assessment: a,
		Baseline:   existingBaseline,
		Reason:     "", // Empty reason should fail
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason is required")
}

func TestWriteBaselineUseCase_Update_NilBaseline(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	a := assessment.NewAssessment("/test")

	_, err := uc.Update(UpdateBaselineInput{
		Assessment: a,
		Baseline:   nil,
		Reason:     testBaselineReason,
	})

	assert.Error(t, err)
}

func TestWriteBaselineUseCase_Merge(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	target := baseline.NewBaseline("/test")
	_ = target.Add(createBaselineFinding("G401", 10), testBaselineReason)

	source1 := baseline.NewBaseline("/test")
	_ = source1.Add(createBaselineFinding("G402", 20), testBaselineReason)

	source2 := baseline.NewBaseline("/test")
	_ = source2.Add(createBaselineFinding("G403", 30), testBaselineReason)

	output, err := uc.Merge(MergeInput{
		Target:  target,
		Sources: []*baseline.Baseline{source1, source2},
	})

	assert.NoError(t, err)
	assert.Equal(t, 2, output.TotalMerged)
	assert.Equal(t, 3, output.Baseline.Count())
}

func TestWriteBaselineUseCase_Merge_NilTarget(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	_, err := uc.Merge(MergeInput{
		Target: nil,
	})

	assert.Error(t, err)
}

func TestWriteBaselineUseCase_Merge_NilSource(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	target := baseline.NewBaseline("/test")

	output, err := uc.Merge(MergeInput{
		Target:  target,
		Sources: []*baseline.Baseline{nil},
	})

	assert.NoError(t, err)
	assert.Equal(t, 0, output.TotalMerged)
}

func TestWriteBaselineUseCase_Filter_NilBaseline(t *testing.T) {
	store := newMockBaselineStore()
	uc := NewWriteBaselineUseCase(store, nil)

	_, err := uc.Filter(FilterInput{
		Baseline: nil,
	})

	assert.Error(t, err)
}

func TestWriteBaselineUseCase_LoadOrCreate_NoExisting(t *testing.T) {
	store := newMockBaselineStore()
	store.exists = false
	uc := NewWriteBaselineUseCase(store, nil)

	b, err := uc.LoadOrCreate("/test")

	assert.NoError(t, err)
	assert.NotNil(t, b)
	assert.Equal(t, 0, b.Count())
}

func TestWriteBaselineUseCase_LoadOrCreate_Existing(t *testing.T) {
	store := newMockBaselineStore()
	store.exists = true
	store.baseline = baseline.NewBaseline("/test")
	_ = store.baseline.Add(createBaselineFinding("G401", 10), testBaselineReason)
	uc := NewWriteBaselineUseCase(store, nil)

	b, err := uc.LoadOrCreate("/test")

	assert.NoError(t, err)
	assert.NotNil(t, b)
	assert.Equal(t, 1, b.Count())
}
