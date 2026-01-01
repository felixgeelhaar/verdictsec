package writers

import (
	"fmt"
	"io"
	"os"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Factory creates writers based on configuration.
type Factory struct{}

// NewFactory creates a new writer factory.
func NewFactory() *Factory {
	return &Factory{}
}

// Create returns a writer for the specified format.
func (f *Factory) Create(format ports.OutputFormat, config ports.OutputConfig) (ports.ArtifactWriter, error) {
	switch format {
	case ports.OutputFormatConsole:
		return f.CreateConsole(config), nil
	case ports.OutputFormatJSON:
		return f.CreateJSON(os.Stdout, true), nil
	case ports.OutputFormatSARIF:
		return nil, fmt.Errorf("SARIF format not yet implemented")
	default:
		return nil, fmt.Errorf("unknown output format: %s", format)
	}
}

// CreateConsole returns a console writer.
func (f *Factory) CreateConsole(config ports.OutputConfig) ports.ConsoleWriter {
	return NewConsoleWriter(
		WithColor(config.Color),
		WithVerbosity(config.Verbosity),
	)
}

// CreateJSON returns a JSON writer.
func (f *Factory) CreateJSON(w io.Writer, pretty bool) ports.JSONWriter {
	return NewJSONWriter(
		WithJSONOutput(w),
		WithPrettyPrint(pretty),
	)
}

// CreateSARIF returns a SARIF writer.
func (f *Factory) CreateSARIF(w io.Writer) ports.SARIFWriter {
	// SARIF writer not implemented yet
	return nil
}

// CreateToFile creates a writer that outputs to a file.
func (f *Factory) CreateToFile(format ports.OutputFormat, path string, config ports.OutputConfig) (ports.ArtifactWriter, error) {
	// Validate path to prevent path traversal attacks
	cleanPath, err := pathutil.ValidatePath(path)
	if err != nil {
		return nil, fmt.Errorf("invalid output path: %w", err)
	}

	file, err := os.Create(cleanPath) // #nosec G304 - path is validated above
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	switch format {
	case ports.OutputFormatJSON:
		w := NewJSONWriter(
			WithJSONOutput(file),
			WithPrettyPrint(true),
		)
		return &fileJSONWriter{JSONWriter: w, file: file}, nil
	case ports.OutputFormatConsole:
		w := NewConsoleWriter(
			WithOutput(file),
			WithColor(false), // No colors in file output
			WithVerbosity(config.Verbosity),
		)
		return &fileConsoleWriter{ConsoleWriter: w, file: file}, nil
	default:
		_ = file.Close()
		return nil, fmt.Errorf("unsupported format for file output: %s", format)
	}
}

// fileJSONWriter wraps JSONWriter with file closing.
type fileJSONWriter struct {
	*JSONWriter
	file *os.File
}

// Close closes the file.
func (w *fileJSONWriter) Close() error {
	return w.file.Close()
}

// fileConsoleWriter wraps ConsoleWriter with file closing.
type fileConsoleWriter struct {
	*ConsoleWriter
	file *os.File
}

// Close closes the file.
func (w *fileConsoleWriter) Close() error {
	return w.file.Close()
}

// Ensure Factory implements the interface.
var _ ports.WriterFactory = (*Factory)(nil)
