package writers

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFactory(t *testing.T) {
	f := NewFactory()

	assert.NotNil(t, f)
}

func TestFactory_Create_Console(t *testing.T) {
	f := NewFactory()

	config := ports.OutputConfig{
		Color:     true,
		Verbosity: ports.VerbosityNormal,
	}

	writer, err := f.Create(ports.OutputFormatConsole, config)

	require.NoError(t, err)
	assert.NotNil(t, writer)

	// Should be a console writer
	_, ok := writer.(*ConsoleWriter)
	assert.True(t, ok)
}

func TestFactory_Create_JSON(t *testing.T) {
	f := NewFactory()

	config := ports.OutputConfig{}

	writer, err := f.Create(ports.OutputFormatJSON, config)

	require.NoError(t, err)
	assert.NotNil(t, writer)

	// Should be a JSON writer
	_, ok := writer.(*JSONWriter)
	assert.True(t, ok)
}

func TestFactory_Create_SARIF_NotImplemented(t *testing.T) {
	f := NewFactory()

	config := ports.OutputConfig{}

	writer, err := f.Create(ports.OutputFormatSARIF, config)

	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "SARIF format not yet implemented")
}

func TestFactory_Create_Unknown(t *testing.T) {
	f := NewFactory()

	config := ports.OutputConfig{}

	writer, err := f.Create(ports.OutputFormat("unknown"), config)

	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "unknown output format")
}

func TestFactory_CreateConsole(t *testing.T) {
	f := NewFactory()

	config := ports.OutputConfig{
		Color:     false,
		Verbosity: ports.VerbosityVerbose,
	}

	writer := f.CreateConsole(config)

	assert.NotNil(t, writer)
	consoleWriter := writer.(*ConsoleWriter)
	assert.False(t, consoleWriter.color)
	assert.Equal(t, ports.VerbosityVerbose, consoleWriter.verbosity)
}

func TestFactory_CreateJSON(t *testing.T) {
	var buf bytes.Buffer
	f := NewFactory()

	writer := f.CreateJSON(&buf, true)

	assert.NotNil(t, writer)
	jsonWriter := writer.(*JSONWriter)
	assert.True(t, jsonWriter.pretty)
	assert.Equal(t, &buf, jsonWriter.out)
}

func TestFactory_CreateSARIF(t *testing.T) {
	var buf bytes.Buffer
	f := NewFactory()

	writer := f.CreateSARIF(&buf)

	// Currently returns nil as not implemented
	assert.Nil(t, writer)
}

func TestFactory_CreateToFile_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "output.json")

	f := NewFactory()
	config := ports.OutputConfig{}

	writer, err := f.CreateToFile(ports.OutputFormatJSON, filePath, config)

	require.NoError(t, err)
	assert.NotNil(t, writer)

	// Close the writer using io.Closer interface
	if closer, ok := writer.(io.Closer); ok {
		err = closer.Close()
		require.NoError(t, err)
	}

	// File should exist
	_, err = os.Stat(filePath)
	assert.NoError(t, err)
}

func TestFactory_CreateToFile_Console(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "output.txt")

	f := NewFactory()
	config := ports.OutputConfig{
		Verbosity: ports.VerbosityNormal,
	}

	writer, err := f.CreateToFile(ports.OutputFormatConsole, filePath, config)

	require.NoError(t, err)
	assert.NotNil(t, writer)

	// Close the writer using io.Closer interface
	if closer, ok := writer.(io.Closer); ok {
		err = closer.Close()
		require.NoError(t, err)
	}

	// File should exist
	_, err = os.Stat(filePath)
	assert.NoError(t, err)
}

func TestFactory_CreateToFile_UnsupportedFormat(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "output.sarif")

	f := NewFactory()
	config := ports.OutputConfig{}

	writer, err := f.CreateToFile(ports.OutputFormatSARIF, filePath, config)

	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "unsupported format for file output")

	// Note: The file is created but then closed on error.
	// This is expected behavior - the file will exist but be empty.
}

func TestFactory_CreateToFile_InvalidPath(t *testing.T) {
	f := NewFactory()
	config := ports.OutputConfig{}

	// Try to create in a non-existent directory
	writer, err := f.CreateToFile(ports.OutputFormatJSON, "/nonexistent/dir/file.json", config)

	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "failed to create output file")
}

func TestFactory_CreateToFile_Console_NoColors(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "output.txt")

	f := NewFactory()
	config := ports.OutputConfig{
		Color: true, // Even if color is requested, file output disables it
	}

	writer, err := f.CreateToFile(ports.OutputFormatConsole, filePath, config)

	require.NoError(t, err)
	assert.NotNil(t, writer)

	// The console writer should have colors disabled for file output
	fileConsole := writer.(*fileConsoleWriter)
	assert.False(t, fileConsole.color)

	if closer, ok := writer.(io.Closer); ok {
		_ = closer.Close()
	}
}

func TestFileJSONWriter_Close(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.json")

	file, err := os.Create(filePath)
	require.NoError(t, err)

	jsonWriter := NewJSONWriter(WithJSONOutput(file))
	fileWriter := &fileJSONWriter{JSONWriter: jsonWriter, file: file}

	err = fileWriter.Close()
	assert.NoError(t, err)

	// Verify file is actually closed by trying to write
	_, err = file.WriteString("test")
	assert.Error(t, err) // Should fail because file is closed
}

func TestFileConsoleWriter_Close(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	file, err := os.Create(filePath)
	require.NoError(t, err)

	consoleWriter := NewConsoleWriter(WithOutput(file))
	fileWriter := &fileConsoleWriter{ConsoleWriter: consoleWriter, file: file}

	err = fileWriter.Close()
	assert.NoError(t, err)

	// Verify file is actually closed by trying to write
	_, err = file.WriteString("test")
	assert.Error(t, err) // Should fail because file is closed
}

func TestFactory_ImplementsInterface(t *testing.T) {
	f := NewFactory()

	var _ ports.WriterFactory = f
}
