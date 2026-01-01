package syft

import (
	"encoding/json"
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// SyftOutput represents the root structure of syft JSON output.
type SyftOutput struct {
	Artifacts             []Artifact  `json:"artifacts"`
	ArtifactRelationships []Relation  `json:"artifactRelationships,omitempty"`
	Source                Source      `json:"source"`
	Distro                *Distro     `json:"distro,omitempty"`
	Descriptor            Descriptor  `json:"descriptor"`
	Schema                SchemaInfo  `json:"schema,omitempty"`
}

// Artifact represents a software component detected by syft.
type Artifact struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      string            `json:"type"`
	FoundBy   string            `json:"foundBy"`
	Locations []Location        `json:"locations"`
	Licenses  []License         `json:"licenses,omitempty"`
	Language  string            `json:"language,omitempty"`
	CPEs      []string          `json:"cpes,omitempty"`
	PURL      string            `json:"purl,omitempty"`
	Metadata  map[string]any    `json:"metadata,omitempty"`
}

// Location represents where an artifact was found.
type Location struct {
	Path        string `json:"path"`
	LayerID     string `json:"layerID,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// License represents license information for an artifact.
type License struct {
	Value          string `json:"value"`
	SPDXExpression string `json:"spdxExpression,omitempty"`
	Type           string `json:"type,omitempty"`
}

// Source represents what was scanned.
type Source struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Version  string      `json:"version,omitempty"`
	Type     string      `json:"type"`
	Metadata SourceMeta  `json:"metadata,omitempty"`
}

// SourceMeta contains additional source metadata.
type SourceMeta struct {
	Path              string   `json:"path,omitempty"`
	ImageID           string   `json:"imageID,omitempty"`
	ManifestDigest    string   `json:"manifestDigest,omitempty"`
	RepoDigests       []string `json:"repoDigests,omitempty"`
	Architecture      string   `json:"architecture,omitempty"`
	OS                string   `json:"os,omitempty"`
}

// Distro represents Linux distribution information.
type Distro struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	Version string `json:"version"`
	IDLike  []string `json:"idLike,omitempty"`
}

// Descriptor contains information about the syft scan.
type Descriptor struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Configuration any    `json:"configuration,omitempty"`
}

// Relation represents a relationship between artifacts.
type Relation struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
	Type   string `json:"type"`
}

// SchemaInfo contains schema version information.
type SchemaInfo struct {
	Version string `json:"version"`
	URL     string `json:"url,omitempty"`
}

// Parser converts syft JSON output to raw findings.
type Parser struct{}

// NewParser creates a new syft parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse converts syft JSON output to raw findings.
// Each artifact becomes a "finding" with type SBOM for tracking purposes.
func (p *Parser) Parse(data []byte) ([]ports.RawFinding, error) {
	if len(data) == 0 {
		return []ports.RawFinding{}, nil
	}

	var output SyftOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal syft output: %w", err)
	}

	findings := make([]ports.RawFinding, 0, len(output.Artifacts))
	for _, artifact := range output.Artifacts {
		finding := p.artifactToRawFinding(artifact, output.Source)
		findings = append(findings, finding)
	}

	return findings, nil
}

// artifactToRawFinding converts a syft artifact to a raw finding.
func (p *Parser) artifactToRawFinding(artifact Artifact, source Source) ports.RawFinding {
	// Build metadata
	metadata := make(map[string]string)
	metadata["artifact_type"] = artifact.Type
	metadata["artifact_id"] = artifact.ID
	metadata["found_by"] = artifact.FoundBy

	if artifact.Language != "" {
		metadata["language"] = artifact.Language
	}

	if artifact.PURL != "" {
		metadata["purl"] = artifact.PURL
	}

	// Add source info
	metadata["source_type"] = source.Type
	metadata["source_name"] = source.Name

	// Extract license info
	if len(artifact.Licenses) > 0 {
		license := artifact.Licenses[0]
		if license.SPDXExpression != "" {
			metadata["license"] = license.SPDXExpression
		} else if license.Value != "" {
			metadata["license"] = license.Value
		}
	}

	// Extract CPE if available
	if len(artifact.CPEs) > 0 {
		metadata["cpe"] = artifact.CPEs[0]
	}

	// Determine file location
	filePath := ""
	if len(artifact.Locations) > 0 {
		filePath = artifact.Locations[0].Path
		if artifact.Locations[0].LayerID != "" {
			metadata["layer_id"] = artifact.Locations[0].LayerID
		}
	}

	// Build message
	message := fmt.Sprintf("Artifact: %s@%s (%s)", artifact.Name, artifact.Version, artifact.Type)

	return ports.RawFinding{
		RuleID:      "sbom-artifact",
		Message:     message,
		Severity:    "INFO", // Artifacts are informational
		Confidence:  "HIGH",
		File:        filePath,
		StartLine:   0,
		StartColumn: 0,
		EndLine:     0,
		EndColumn:   0,
		Snippet:     "",
		Metadata:    metadata,
	}
}

// ParseOutput parses the raw syft data into a structured format.
func (p *Parser) ParseOutput(data []byte) (*SyftOutput, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var output SyftOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal syft output: %w", err)
	}

	return &output, nil
}

// GetArtifactCount returns the number of artifacts in the SBOM.
func (p *Parser) GetArtifactCount(data []byte) (int, error) {
	output, err := p.ParseOutput(data)
	if err != nil {
		return 0, err
	}
	if output == nil {
		return 0, nil
	}
	return len(output.Artifacts), nil
}

// GetSourceInfo returns information about what was scanned.
func (p *Parser) GetSourceInfo(data []byte) (*Source, error) {
	output, err := p.ParseOutput(data)
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, nil
	}
	return &output.Source, nil
}

// GetRelationships returns the dependency relationships between artifacts.
func (p *Parser) GetRelationships(data []byte) ([]Relation, error) {
	output, err := p.ParseOutput(data)
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, nil
	}
	return output.ArtifactRelationships, nil
}
