package sbom

// Format represents the SBOM format type.
type Format string

// Supported SBOM formats.
const (
	FormatCycloneDX Format = "cyclonedx"
	FormatSyft      Format = "syft"
	FormatSPDX      Format = "spdx"
	FormatUnknown   Format = "unknown"
)

// String returns the string representation of the format.
func (f Format) String() string {
	return string(f)
}

// IsValid returns true if the format is a known format.
func (f Format) IsValid() bool {
	switch f {
	case FormatCycloneDX, FormatSyft, FormatSPDX:
		return true
	default:
		return false
	}
}

// ParseFormat parses a string into a Format.
func ParseFormat(s string) Format {
	switch s {
	case "cyclonedx", "CycloneDX", "CYCLONEDX":
		return FormatCycloneDX
	case "syft", "Syft", "SYFT":
		return FormatSyft
	case "spdx", "SPDX", "Spdx":
		return FormatSPDX
	default:
		return FormatUnknown
	}
}
