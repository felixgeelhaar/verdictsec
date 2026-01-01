package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Location represents a source code location for a security finding.
// It is a value object that is immutable and comparable.
// Paths are normalized to use forward slashes for determinism across platforms.
type Location struct {
	file      string
	line      int
	column    int
	endLine   int
	endColumn int
}

// NewLocation creates a new Location with the given parameters.
// The file path is normalized to use forward slashes.
func NewLocation(file string, line, column, endLine, endColumn int) Location {
	// Normalize path separators for determinism across platforms
	// Use strings.ReplaceAll for consistent behavior across all platforms
	normalizedFile := strings.ReplaceAll(file, "\\", "/")
	// Remove leading ./ if present for consistency
	normalizedFile = strings.TrimPrefix(normalizedFile, "./")

	return Location{
		file:      normalizedFile,
		line:      line,
		column:    column,
		endLine:   endLine,
		endColumn: endColumn,
	}
}

// NewLocationSimple creates a Location with just file and line information.
func NewLocationSimple(file string, line int) Location {
	return NewLocation(file, line, 0, 0, 0)
}

// File returns the normalized file path.
func (l Location) File() string { return l.file }

// Line returns the starting line number.
func (l Location) Line() int { return l.line }

// Column returns the starting column number.
func (l Location) Column() int { return l.column }

// EndLine returns the ending line number.
func (l Location) EndLine() int { return l.endLine }

// EndColumn returns the ending column number.
func (l Location) EndColumn() int { return l.endColumn }

// String returns a human-readable string representation.
func (l Location) String() string {
	if l.column > 0 {
		return fmt.Sprintf("%s:%d:%d", l.file, l.line, l.column)
	}
	if l.line > 0 {
		return fmt.Sprintf("%s:%d", l.file, l.line)
	}
	return l.file
}

// Canonical returns a stable string for fingerprinting.
// This format is used for deterministic fingerprint generation.
func (l Location) Canonical() string {
	return fmt.Sprintf("%s:%d:%d", l.file, l.line, l.column)
}

// Equals compares two locations for equality.
func (l Location) Equals(other Location) bool {
	return l.file == other.file &&
		l.line == other.line &&
		l.column == other.column &&
		l.endLine == other.endLine &&
		l.endColumn == other.endColumn
}

// SamePosition returns true if the locations point to the same starting position.
func (l Location) SamePosition(other Location) bool {
	return l.file == other.file &&
		l.line == other.line &&
		l.column == other.column
}

// IsZero returns true if the location is empty.
func (l Location) IsZero() bool {
	return l.file == "" && l.line == 0 && l.column == 0
}

// HasRange returns true if the location has end position information.
func (l Location) HasRange() bool {
	return l.endLine > 0 || l.endColumn > 0
}

// locationJSON is used for JSON marshaling/unmarshaling.
type locationJSON struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Column    int    `json:"column,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	EndColumn int    `json:"end_column,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (l Location) MarshalJSON() ([]byte, error) {
	return json.Marshal(locationJSON{
		File:      l.file,
		Line:      l.line,
		Column:    l.column,
		EndLine:   l.endLine,
		EndColumn: l.endColumn,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (l *Location) UnmarshalJSON(data []byte) error {
	var lj locationJSON
	if err := json.Unmarshal(data, &lj); err != nil {
		return err
	}
	*l = NewLocation(lj.File, lj.Line, lj.Column, lj.EndLine, lj.EndColumn)
	return nil
}
