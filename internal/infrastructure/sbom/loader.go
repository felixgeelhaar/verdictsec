package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	domainsbom "github.com/felixgeelhaar/verdictsec/internal/domain/sbom"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/cyclonedx"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/syft"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Loader implements ports.SBOMLoader.
type Loader struct{}

// NewLoader creates a new SBOM loader.
func NewLoader() *Loader {
	return &Loader{}
}

// LoadFromFile loads an SBOM from a file path.
// It auto-detects the format from file contents.
func (l *Loader) LoadFromFile(ctx context.Context, path string) (*domainsbom.SBOM, error) {
	// Validate path to prevent directory traversal attacks
	cleanPath, err := pathutil.ValidatePath(path)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	data, err := os.ReadFile(cleanPath) // #nosec G304 - path is validated above
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Auto-detect format
	format := detectFormat(data)
	if format == domainsbom.FormatUnknown {
		return nil, fmt.Errorf("unknown SBOM format in file: %s", path)
	}

	return l.LoadFromBytes(ctx, data, format)
}

// LoadFromReader loads an SBOM from a reader.
func (l *Loader) LoadFromReader(ctx context.Context, r io.Reader, format domainsbom.Format) (*domainsbom.SBOM, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return l.LoadFromBytes(ctx, data, format)
}

// LoadFromBytes loads an SBOM from raw bytes.
func (l *Loader) LoadFromBytes(_ context.Context, data []byte, format domainsbom.Format) (*domainsbom.SBOM, error) {
	switch format {
	case domainsbom.FormatCycloneDX:
		return l.parseCycloneDX(data)
	case domainsbom.FormatSyft:
		return l.parseSyft(data)
	case domainsbom.FormatUnknown:
		// Try auto-detection
		detected := detectFormat(data)
		if detected == domainsbom.FormatUnknown {
			return nil, fmt.Errorf("unable to detect SBOM format")
		}
		return l.LoadFromBytes(nil, data, detected)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}

// parseCycloneDX converts CycloneDX JSON to domain SBOM.
func (l *Loader) parseCycloneDX(data []byte) (*domainsbom.SBOM, error) {
	parser := cyclonedx.NewParser()
	bom, err := parser.ParseBOM(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX: %w", err)
	}
	if bom == nil {
		return nil, fmt.Errorf("empty CycloneDX SBOM")
	}

	// Convert components
	components := make([]domainsbom.Component, 0, len(bom.Components))
	for _, c := range bom.Components {
		license := ""
		if len(c.Licenses) > 0 {
			if c.Licenses[0].License.ID != "" {
				license = c.Licenses[0].License.ID
			} else {
				license = c.Licenses[0].License.Name
			}
		}

		comp := domainsbom.NewComponentFull(
			c.Name,
			c.Version,
			c.PURL,
			license,
			"", // language not in CycloneDX component
			c.Type,
		)
		components = append(components, comp)
	}

	// Parse timestamp
	var timestamp time.Time
	if bom.Metadata.Timestamp != "" {
		t, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp)
		if err == nil {
			timestamp = t
		}
	}
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// Get tool info
	toolName := ""
	toolVer := ""
	if len(bom.Metadata.Tools) > 0 {
		toolName = bom.Metadata.Tools[0].Name
		toolVer = bom.Metadata.Tools[0].Version
	}

	// Get source from metadata component
	source := ""
	if bom.Metadata.Component != nil {
		source = bom.Metadata.Component.Name
	}

	return domainsbom.NewSBOMFull(
		domainsbom.FormatCycloneDX,
		source,
		"module", // CycloneDX from cyclonedx-gomod is module-level
		components,
		timestamp,
		toolName,
		toolVer,
	), nil
}

// parseSyft converts Syft JSON to domain SBOM.
func (l *Loader) parseSyft(data []byte) (*domainsbom.SBOM, error) {
	parser := syft.NewParser()
	output, err := parser.ParseOutput(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Syft output: %w", err)
	}
	if output == nil {
		return nil, fmt.Errorf("empty Syft SBOM")
	}

	// Convert artifacts to components
	components := make([]domainsbom.Component, 0, len(output.Artifacts))
	for _, a := range output.Artifacts {
		license := ""
		if len(a.Licenses) > 0 {
			if a.Licenses[0].SPDXExpression != "" {
				license = a.Licenses[0].SPDXExpression
			} else {
				license = a.Licenses[0].Value
			}
		}

		comp := domainsbom.NewComponentFull(
			a.Name,
			a.Version,
			a.PURL,
			license,
			a.Language,
			a.Type,
		)
		components = append(components, comp)
	}

	return domainsbom.NewSBOMFull(
		domainsbom.FormatSyft,
		output.Source.Name,
		output.Source.Type,
		components,
		time.Now(), // Syft doesn't have timestamp in output
		output.Descriptor.Name,
		output.Descriptor.Version,
	), nil
}

// detectFormat attempts to detect the SBOM format from raw bytes.
func detectFormat(data []byte) domainsbom.Format {
	// Try to parse as JSON first
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		return domainsbom.FormatUnknown
	}

	// Check for CycloneDX markers
	if bomFormat, ok := generic["bomFormat"].(string); ok {
		if strings.EqualFold(bomFormat, "CycloneDX") {
			return domainsbom.FormatCycloneDX
		}
	}

	// Check for Syft markers
	if _, hasArtifacts := generic["artifacts"]; hasArtifacts {
		if descriptor, ok := generic["descriptor"].(map[string]any); ok {
			if name, ok := descriptor["name"].(string); ok && name == "syft" {
				return domainsbom.FormatSyft
			}
		}
		// Has artifacts but not syft - still treat as syft format
		return domainsbom.FormatSyft
	}

	// Check for SPDX markers
	if _, hasSpdxVersion := generic["spdxVersion"]; hasSpdxVersion {
		return domainsbom.FormatSPDX
	}

	return domainsbom.FormatUnknown
}
