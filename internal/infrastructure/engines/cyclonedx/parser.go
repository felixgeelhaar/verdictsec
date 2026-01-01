package cyclonedx

import (
	"encoding/json"
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// CycloneDXBOM represents a CycloneDX SBOM.
type CycloneDXBOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     BOMMetadata  `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// BOMMetadata contains SBOM metadata.
type BOMMetadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     []BOMTool  `json:"tools,omitempty"`
	Component *Component `json:"component,omitempty"`
}

// BOMTool represents a tool used to generate the SBOM.
type BOMTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component represents a software component.
type Component struct {
	Type       string              `json:"type"`
	BOMRef     string              `json:"bom-ref"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	Scope      string              `json:"scope,omitempty"`
	Hashes     []ComponentHash     `json:"hashes,omitempty"`
	Licenses   []ComponentLicense  `json:"licenses,omitempty"`
	PURL       string              `json:"purl,omitempty"`
	ExternalRefs []ExternalRef     `json:"externalReferences,omitempty"`
}

// ComponentHash contains hash information.
type ComponentHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// ComponentLicense contains license information.
type ComponentLicense struct {
	License LicenseInfo `json:"license"`
}

// LicenseInfo contains license details.
type LicenseInfo struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// ExternalRef contains external reference information.
type ExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Dependency represents a dependency relationship.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// Parser converts CycloneDX SBOM to component information.
type Parser struct{}

// NewParser creates a new CycloneDX parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse converts CycloneDX JSON output to raw findings.
// Each component becomes a "finding" with type SBOM for tracking purposes.
func (p *Parser) Parse(data []byte) ([]ports.RawFinding, error) {
	if len(data) == 0 {
		return []ports.RawFinding{}, nil
	}

	var bom CycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CycloneDX output: %w", err)
	}

	findings := make([]ports.RawFinding, 0, len(bom.Components))
	for _, component := range bom.Components {
		finding := p.componentToRawFinding(component)
		findings = append(findings, finding)
	}

	return findings, nil
}

// componentToRawFinding converts a CycloneDX component to a raw finding.
func (p *Parser) componentToRawFinding(component Component) ports.RawFinding {
	// Build metadata
	metadata := make(map[string]string)
	metadata["component_type"] = component.Type
	metadata["bom_ref"] = component.BOMRef

	if component.PURL != "" {
		metadata["purl"] = component.PURL
	}

	if component.Scope != "" {
		metadata["scope"] = component.Scope
	}

	// Extract license info
	if len(component.Licenses) > 0 {
		license := component.Licenses[0].License
		if license.ID != "" {
			metadata["license"] = license.ID
		} else if license.Name != "" {
			metadata["license"] = license.Name
		}
	}

	// Extract hash if available
	for _, hash := range component.Hashes {
		metadata[fmt.Sprintf("hash_%s", hash.Alg)] = hash.Content
	}

	// Build message
	message := fmt.Sprintf("Component: %s@%s", component.Name, component.Version)

	return ports.RawFinding{
		RuleID:      "sbom-component",
		Message:     message,
		Severity:    "INFO", // Components are informational
		Confidence:  "HIGH",
		File:        "go.mod",
		StartLine:   0,
		StartColumn: 0,
		EndLine:     0,
		EndColumn:   0,
		Snippet:     "",
		Metadata:    metadata,
	}
}

// ParseBOM parses the raw SBOM data into a structured format.
func (p *Parser) ParseBOM(data []byte) (*CycloneDXBOM, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var bom CycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CycloneDX output: %w", err)
	}

	return &bom, nil
}

// GetComponentCount returns the number of components in the SBOM.
func (p *Parser) GetComponentCount(data []byte) (int, error) {
	bom, err := p.ParseBOM(data)
	if err != nil {
		return 0, err
	}
	if bom == nil {
		return 0, nil
	}
	return len(bom.Components), nil
}

// GetDependencyTree returns the dependency relationships.
func (p *Parser) GetDependencyTree(data []byte) ([]Dependency, error) {
	bom, err := p.ParseBOM(data)
	if err != nil {
		return nil, err
	}
	if bom == nil {
		return nil, nil
	}
	return bom.Dependencies, nil
}
