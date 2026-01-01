package writers

import (
	"errors"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/stretchr/testify/assert"
)

func TestNewSilentWriter(t *testing.T) {
	w := NewSilentWriter()
	assert.NotNil(t, w)
}

func TestSilentWriter_WriteAssessment(t *testing.T) {
	w := NewSilentWriter()

	a := assessment.NewAssessment("/test")
	loc := finding.NewLocation("test.go", 1, 1, 1, 10)
	f := finding.NewFinding(finding.FindingTypeSAST, "gosec", "G101", "Test", finding.SeverityHigh, loc)
	a.AddFinding(f)

	result := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f},
		Reasons:     []string{"Test reason"},
	}

	err := w.WriteAssessment(a, result)
	assert.NoError(t, err)
}

func TestSilentWriter_WriteSummary(t *testing.T) {
	w := NewSilentWriter()

	a := assessment.NewAssessment("/test")
	result := services.EvaluationResult{
		Decision: assessment.DecisionPass,
		Reasons:  []string{"No findings"},
	}

	err := w.WriteSummary(a, result)
	assert.NoError(t, err)
}

func TestSilentWriter_WriteProgress(t *testing.T) {
	w := NewSilentWriter()

	err := w.WriteProgress("Running scan...")
	assert.NoError(t, err)
}

func TestSilentWriter_WriteError(t *testing.T) {
	w := NewSilentWriter()

	err := w.WriteError(errors.New("test error"))
	assert.NoError(t, err)
}

func TestSilentWriter_Flush(t *testing.T) {
	w := NewSilentWriter()

	err := w.Flush()
	assert.NoError(t, err)
}
