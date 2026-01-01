package ports

import (
	"errors"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/stretchr/testify/assert"
)

// mockWriter is a test implementation of ArtifactWriter
type mockWriter struct {
	assessments []string
	summaries   []string
	progress    []string
	errors      []error
	shouldFail  bool
}

func (m *mockWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	if m.shouldFail {
		return errors.New("write failed")
	}
	m.assessments = append(m.assessments, a.ID())
	return nil
}

func (m *mockWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	if m.shouldFail {
		return errors.New("write failed")
	}
	m.summaries = append(m.summaries, a.ID())
	return nil
}

func (m *mockWriter) WriteProgress(message string) error {
	if m.shouldFail {
		return errors.New("write failed")
	}
	m.progress = append(m.progress, message)
	return nil
}

func (m *mockWriter) WriteError(err error) error {
	if m.shouldFail {
		return errors.New("write failed")
	}
	m.errors = append(m.errors, err)
	return nil
}

func (m *mockWriter) Flush() error {
	if m.shouldFail {
		return errors.New("flush failed")
	}
	return nil
}

func TestNewMultiWriter(t *testing.T) {
	w1 := &mockWriter{}
	w2 := &mockWriter{}

	multi := NewMultiWriter(w1, w2)

	assert.NotNil(t, multi)
}

func TestMultiWriter_WriteAssessment(t *testing.T) {
	w1 := &mockWriter{}
	w2 := &mockWriter{}
	multi := NewMultiWriter(w1, w2)

	a := assessment.NewAssessment("/test")
	result := services.EvaluationResult{}

	err := multi.WriteAssessment(a, result)

	assert.NoError(t, err)
	assert.Len(t, w1.assessments, 1)
	assert.Len(t, w2.assessments, 1)
}

func TestMultiWriter_WriteAssessment_Error(t *testing.T) {
	w1 := &mockWriter{shouldFail: true}
	w2 := &mockWriter{}
	multi := NewMultiWriter(w1, w2)

	a := assessment.NewAssessment("/test")
	result := services.EvaluationResult{}

	err := multi.WriteAssessment(a, result)

	assert.Error(t, err)
}

func TestMultiWriter_WriteSummary(t *testing.T) {
	w1 := &mockWriter{}
	w2 := &mockWriter{}
	multi := NewMultiWriter(w1, w2)

	a := assessment.NewAssessment("/test")
	result := services.EvaluationResult{}

	err := multi.WriteSummary(a, result)

	assert.NoError(t, err)
	assert.Len(t, w1.summaries, 1)
	assert.Len(t, w2.summaries, 1)
}

func TestMultiWriter_WriteSummary_Error(t *testing.T) {
	w1 := &mockWriter{shouldFail: true}
	multi := NewMultiWriter(w1)

	a := assessment.NewAssessment("/test")
	result := services.EvaluationResult{}

	err := multi.WriteSummary(a, result)

	assert.Error(t, err)
}

func TestMultiWriter_WriteProgress(t *testing.T) {
	w1 := &mockWriter{}
	w2 := &mockWriter{}
	multi := NewMultiWriter(w1, w2)

	err := multi.WriteProgress("test message")

	assert.NoError(t, err)
	assert.Equal(t, []string{"test message"}, w1.progress)
	assert.Equal(t, []string{"test message"}, w2.progress)
}

func TestMultiWriter_WriteProgress_Error(t *testing.T) {
	w1 := &mockWriter{shouldFail: true}
	multi := NewMultiWriter(w1)

	err := multi.WriteProgress("test")

	assert.Error(t, err)
}

func TestMultiWriter_WriteError(t *testing.T) {
	w1 := &mockWriter{}
	w2 := &mockWriter{}
	multi := NewMultiWriter(w1, w2)

	testErr := errors.New("test error")
	err := multi.WriteError(testErr)

	assert.NoError(t, err)
	assert.Len(t, w1.errors, 1)
	assert.Len(t, w2.errors, 1)
}

func TestMultiWriter_WriteError_Error(t *testing.T) {
	w1 := &mockWriter{shouldFail: true}
	multi := NewMultiWriter(w1)

	err := multi.WriteError(errors.New("test"))

	assert.Error(t, err)
}

func TestMultiWriter_Flush(t *testing.T) {
	w1 := &mockWriter{}
	w2 := &mockWriter{}
	multi := NewMultiWriter(w1, w2)

	err := multi.Flush()

	assert.NoError(t, err)
}

func TestMultiWriter_Flush_Error(t *testing.T) {
	w1 := &mockWriter{shouldFail: true}
	multi := NewMultiWriter(w1)

	err := multi.Flush()

	assert.Error(t, err)
}
