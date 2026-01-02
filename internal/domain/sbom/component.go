package sbom

import (
	"fmt"
	"strings"
)

// Component represents a software component in an SBOM.
// It is a value object - immutable and compared by value.
type Component struct {
	name     string
	version  string
	purl     string   // Package URL - primary key for matching
	license  string   // SPDX license expression
	language string   // Programming language (if known)
	typ      string   // Component type (library, application, etc.)
}

// NewComponent creates a new Component.
func NewComponent(name, version, purl string) Component {
	return Component{
		name:    name,
		version: version,
		purl:    purl,
	}
}

// NewComponentFull creates a new Component with all fields.
func NewComponentFull(name, version, purl, license, language, typ string) Component {
	return Component{
		name:     name,
		version:  version,
		purl:     purl,
		license:  license,
		language: language,
		typ:      typ,
	}
}

// Name returns the component name.
func (c Component) Name() string { return c.name }

// Version returns the component version.
func (c Component) Version() string { return c.version }

// PURL returns the Package URL.
func (c Component) PURL() string { return c.purl }

// License returns the SPDX license expression.
func (c Component) License() string { return c.license }

// Language returns the programming language.
func (c Component) Language() string { return c.language }

// Type returns the component type.
func (c Component) Type() string { return c.typ }

// Key returns a unique identifier for the component.
// PURL is preferred if available, otherwise name is used.
func (c Component) Key() string {
	if c.purl != "" {
		return c.purl
	}
	return c.name
}

// KeyWithoutVersion returns the key without version for matching.
// This enables detecting version changes of the same component.
func (c Component) KeyWithoutVersion() string {
	if c.purl != "" {
		// Remove version from PURL: pkg:golang/github.com/foo@v1.0.0 -> pkg:golang/github.com/foo
		if idx := strings.LastIndex(c.purl, "@"); idx != -1 {
			return c.purl[:idx]
		}
		return c.purl
	}
	return c.name
}

// String returns a human-readable representation.
func (c Component) String() string {
	if c.version != "" {
		return fmt.Sprintf("%s@%s", c.name, c.version)
	}
	return c.name
}

// Equal returns true if two components are identical.
func (c Component) Equal(other Component) bool {
	return c.name == other.name &&
		c.version == other.version &&
		c.purl == other.purl &&
		c.license == other.license
}

// VersionChange describes the type of version change.
type VersionChange string

// Version change types.
const (
	VersionUnchanged VersionChange = "unchanged"
	VersionMajor     VersionChange = "major"
	VersionMinor     VersionChange = "minor"
	VersionPatch     VersionChange = "patch"
	VersionOther     VersionChange = "other" // Non-semver or unparseable
)

// CompareVersion compares two version strings and returns the change type.
// This is a best-effort comparison for semver-like versions.
func CompareVersion(oldVer, newVer string) VersionChange {
	if oldVer == newVer {
		return VersionUnchanged
	}

	// Normalize versions by removing 'v' prefix
	oldVer = strings.TrimPrefix(oldVer, "v")
	newVer = strings.TrimPrefix(newVer, "v")

	oldParts := strings.Split(oldVer, ".")
	newParts := strings.Split(newVer, ".")

	// Need at least 1 part to compare
	if len(oldParts) == 0 || len(newParts) == 0 {
		return VersionOther
	}

	// Compare major
	if len(oldParts) >= 1 && len(newParts) >= 1 {
		if oldParts[0] != newParts[0] {
			return VersionMajor
		}
	}

	// Compare minor
	if len(oldParts) >= 2 && len(newParts) >= 2 {
		if oldParts[1] != newParts[1] {
			return VersionMinor
		}
	}

	// Compare patch
	if len(oldParts) >= 3 && len(newParts) >= 3 {
		if oldParts[2] != newParts[2] {
			return VersionPatch
		}
	}

	// Versions differ but we couldn't classify
	return VersionOther
}
