package ports

import (
	"io"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// ArtifactWriter defines the interface for writing scan results.
type ArtifactWriter interface {
	// WriteAssessment writes the assessment result.
	WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error

	// WriteSummary writes a brief summary of the scan.
	WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error

	// WriteProgress writes progress updates during scan.
	WriteProgress(message string) error

	// WriteError writes error messages.
	WriteError(err error) error

	// Flush ensures all output is written.
	Flush() error
}

// ConsoleWriter writes to stdout/stderr with optional colors.
type ConsoleWriter interface {
	ArtifactWriter

	// SetColor enables or disables colored output.
	SetColor(enabled bool)

	// SetVerbosity sets the output detail level.
	SetVerbosity(v Verbosity)
}

// FileWriter writes to files.
type FileWriter interface {
	ArtifactWriter

	// SetOutput sets the output destination.
	SetOutput(w io.Writer)

	// Close closes any open file handles.
	Close() error
}

// JSONWriter writes JSON output.
type JSONWriter interface {
	FileWriter

	// SetPretty enables or disables pretty-printed JSON.
	SetPretty(enabled bool)
}

// SARIFWriter writes SARIF format output.
type SARIFWriter interface {
	FileWriter
}

// WriterFactory creates writers based on configuration.
type WriterFactory interface {
	// Create returns a writer for the specified format.
	Create(format OutputFormat, config OutputConfig) (ArtifactWriter, error)

	// CreateConsole returns a console writer.
	CreateConsole(config OutputConfig) ConsoleWriter

	// CreateJSON returns a JSON writer.
	CreateJSON(w io.Writer, pretty bool) JSONWriter

	// CreateSARIF returns a SARIF writer.
	CreateSARIF(w io.Writer) SARIFWriter
}

// MultiWriter writes to multiple destinations.
type MultiWriter struct {
	writers []ArtifactWriter
}

// NewMultiWriter creates a writer that writes to all provided writers.
func NewMultiWriter(writers ...ArtifactWriter) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// WriteAssessment writes to all writers.
func (m *MultiWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	for _, w := range m.writers {
		if err := w.WriteAssessment(a, result); err != nil {
			return err
		}
	}
	return nil
}

// WriteSummary writes to all writers.
func (m *MultiWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	for _, w := range m.writers {
		if err := w.WriteSummary(a, result); err != nil {
			return err
		}
	}
	return nil
}

// WriteProgress writes to all writers.
func (m *MultiWriter) WriteProgress(message string) error {
	for _, w := range m.writers {
		if err := w.WriteProgress(message); err != nil {
			return err
		}
	}
	return nil
}

// WriteError writes to all writers.
func (m *MultiWriter) WriteError(err error) error {
	for _, w := range m.writers {
		if writeErr := w.WriteError(err); writeErr != nil {
			return writeErr
		}
	}
	return nil
}

// Flush flushes all writers.
func (m *MultiWriter) Flush() error {
	for _, w := range m.writers {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return nil
}
