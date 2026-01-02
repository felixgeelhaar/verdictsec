package sbom

import (
	"time"
)

// SBOM represents a Software Bill of Materials.
// It is an aggregate containing components and metadata.
type SBOM struct {
	format     Format
	source     string      // What was scanned (path, image, etc.)
	sourceType string      // Type of source (directory, container, etc.)
	components []Component
	timestamp  time.Time
	toolName   string // Tool that generated the SBOM
	toolVer    string // Tool version
}

// NewSBOM creates a new SBOM.
func NewSBOM(format Format, source string, components []Component) *SBOM {
	return &SBOM{
		format:     format,
		source:     source,
		components: components,
		timestamp:  time.Now(),
	}
}

// NewSBOMFull creates a new SBOM with all metadata.
func NewSBOMFull(
	format Format,
	source, sourceType string,
	components []Component,
	timestamp time.Time,
	toolName, toolVer string,
) *SBOM {
	return &SBOM{
		format:     format,
		source:     source,
		sourceType: sourceType,
		components: components,
		timestamp:  timestamp,
		toolName:   toolName,
		toolVer:    toolVer,
	}
}

// Format returns the SBOM format.
func (s *SBOM) Format() Format { return s.format }

// Source returns what was scanned.
func (s *SBOM) Source() string { return s.source }

// SourceType returns the type of source.
func (s *SBOM) SourceType() string { return s.sourceType }

// Components returns all components in the SBOM.
func (s *SBOM) Components() []Component { return s.components }

// ComponentCount returns the number of components.
func (s *SBOM) ComponentCount() int { return len(s.components) }

// Timestamp returns when the SBOM was generated.
func (s *SBOM) Timestamp() time.Time { return s.timestamp }

// ToolName returns the name of the tool that generated the SBOM.
func (s *SBOM) ToolName() string { return s.toolName }

// ToolVersion returns the version of the tool.
func (s *SBOM) ToolVersion() string { return s.toolVer }

// ComponentByKey returns a component by its key (PURL or name).
func (s *SBOM) ComponentByKey(key string) (Component, bool) {
	for _, c := range s.components {
		if c.Key() == key {
			return c, true
		}
	}
	return Component{}, false
}

// ComponentsByLanguage returns components filtered by language.
func (s *SBOM) ComponentsByLanguage(lang string) []Component {
	var result []Component
	for _, c := range s.components {
		if c.Language() == lang {
			result = append(result, c)
		}
	}
	return result
}

// ComponentsByType returns components filtered by type.
func (s *SBOM) ComponentsByType(typ string) []Component {
	var result []Component
	for _, c := range s.components {
		if c.Type() == typ {
			result = append(result, c)
		}
	}
	return result
}

// Licenses returns a deduplicated list of licenses used.
func (s *SBOM) Licenses() []string {
	seen := make(map[string]bool)
	var result []string
	for _, c := range s.components {
		if c.License() != "" && !seen[c.License()] {
			seen[c.License()] = true
			result = append(result, c.License())
		}
	}
	return result
}

// Languages returns a deduplicated list of languages.
func (s *SBOM) Languages() []string {
	seen := make(map[string]bool)
	var result []string
	for _, c := range s.components {
		if c.Language() != "" && !seen[c.Language()] {
			seen[c.Language()] = true
			result = append(result, c.Language())
		}
	}
	return result
}

// ComponentMap returns components indexed by their key without version.
// This enables efficient lookup for diff operations.
func (s *SBOM) ComponentMap() map[string]Component {
	result := make(map[string]Component)
	for _, c := range s.components {
		result[c.KeyWithoutVersion()] = c
	}
	return result
}
