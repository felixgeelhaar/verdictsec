package writers

import (
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// SilentWriter discards all output, useful for programmatic contexts like MCP.
type SilentWriter struct{}

// NewSilentWriter creates a new silent writer.
func NewSilentWriter() *SilentWriter {
	return &SilentWriter{}
}

// WriteAssessment discards the assessment output.
func (w *SilentWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	return nil
}

// WriteSummary discards the summary output.
func (w *SilentWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	return nil
}

// WriteProgress discards progress messages.
func (w *SilentWriter) WriteProgress(message string) error {
	return nil
}

// WriteError discards error messages.
func (w *SilentWriter) WriteError(err error) error {
	return nil
}

// Flush is a no-op for SilentWriter.
func (w *SilentWriter) Flush() error {
	return nil
}
