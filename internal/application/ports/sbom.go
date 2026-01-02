package ports

import (
	"context"
	"io"

	"github.com/felixgeelhaar/verdictsec/internal/domain/sbom"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// SBOMLoader loads SBOMs from various sources.
type SBOMLoader interface {
	// LoadFromFile loads an SBOM from a file path.
	LoadFromFile(ctx context.Context, path string) (*sbom.SBOM, error)

	// LoadFromReader loads an SBOM from a reader.
	LoadFromReader(ctx context.Context, r io.Reader, format sbom.Format) (*sbom.SBOM, error)

	// LoadFromBytes loads an SBOM from raw bytes.
	LoadFromBytes(ctx context.Context, data []byte, format sbom.Format) (*sbom.SBOM, error)
}

// SBOMDiffWriter writes SBOM diff results to various formats.
type SBOMDiffWriter interface {
	// Write outputs the diff result.
	Write(result services.SBOMDiffResult) error
}

// SBOMDiffWriterFactory creates diff writers for different output formats.
type SBOMDiffWriterFactory interface {
	// Console creates a writer for colored console output.
	Console(w io.Writer, colors bool) SBOMDiffWriter

	// JSON creates a writer for JSON output.
	JSON(w io.Writer, pretty bool) SBOMDiffWriter

	// Markdown creates a writer for Markdown output.
	Markdown(w io.Writer) SBOMDiffWriter
}

// SBOMDiffOutput represents the serializable output of an SBOM diff.
// Used for JSON output format.
type SBOMDiffOutput struct {
	Base   SBOMSummary       `json:"base"`
	Target SBOMSummary       `json:"target"`
	Stats  SBOMDiffStatsOut  `json:"stats"`
	Added  []ComponentOut    `json:"added,omitempty"`
	Removed []ComponentOut   `json:"removed,omitempty"`
	Modified []ComponentDiffOut `json:"modified,omitempty"`
}

// SBOMSummary contains SBOM metadata for output.
type SBOMSummary struct {
	Source         string `json:"source"`
	SourceType     string `json:"source_type,omitempty"`
	Format         string `json:"format"`
	ComponentCount int    `json:"component_count"`
	Timestamp      string `json:"timestamp,omitempty"`
	Tool           string `json:"tool,omitempty"`
}

// SBOMDiffStatsOut contains diff statistics for output.
type SBOMDiffStatsOut struct {
	Added          int `json:"added"`
	Removed        int `json:"removed"`
	Modified       int `json:"modified"`
	Unchanged      int `json:"unchanged"`
	MajorChanges   int `json:"major_changes"`
	MinorChanges   int `json:"minor_changes"`
	PatchChanges   int `json:"patch_changes"`
	LicenseChanges int `json:"license_changes"`
}

// ComponentOut represents a component for output.
type ComponentOut struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	PURL     string `json:"purl,omitempty"`
	License  string `json:"license,omitempty"`
	Language string `json:"language,omitempty"`
	Type     string `json:"type,omitempty"`
}

// ComponentDiffOut represents a component change for output.
type ComponentDiffOut struct {
	Name          string `json:"name"`
	OldVersion    string `json:"old_version"`
	NewVersion    string `json:"new_version"`
	VersionChange string `json:"version_change"` // major, minor, patch, other
	OldLicense    string `json:"old_license,omitempty"`
	NewLicense    string `json:"new_license,omitempty"`
	LicenseChange bool   `json:"license_change"`
}

// ConvertToOutput converts a diff result to output format.
func ConvertToOutput(result services.SBOMDiffResult) SBOMDiffOutput {
	out := SBOMDiffOutput{
		Stats: convertStats(result.Stats()),
	}

	if result.Base != nil {
		out.Base = SBOMSummary{
			Source:         result.Base.Source(),
			SourceType:     result.Base.SourceType(),
			Format:         result.Base.Format().String(),
			ComponentCount: result.Base.ComponentCount(),
			Timestamp:      result.Base.Timestamp().Format("2006-01-02T15:04:05Z"),
			Tool:           result.Base.ToolName(),
		}
	}

	if result.Target != nil {
		out.Target = SBOMSummary{
			Source:         result.Target.Source(),
			SourceType:     result.Target.SourceType(),
			Format:         result.Target.Format().String(),
			ComponentCount: result.Target.ComponentCount(),
			Timestamp:      result.Target.Timestamp().Format("2006-01-02T15:04:05Z"),
			Tool:           result.Target.ToolName(),
		}
	}

	for _, c := range result.Added {
		out.Added = append(out.Added, convertComponent(c))
	}

	for _, c := range result.Removed {
		out.Removed = append(out.Removed, convertComponent(c))
	}

	for _, d := range result.Modified {
		out.Modified = append(out.Modified, ComponentDiffOut{
			Name:          d.Target.Name(),
			OldVersion:    d.Base.Version(),
			NewVersion:    d.Target.Version(),
			VersionChange: string(d.VersionChange),
			OldLicense:    d.Base.License(),
			NewLicense:    d.Target.License(),
			LicenseChange: d.LicenseChange,
		})
	}

	return out
}

func convertStats(s services.SBOMDiffStats) SBOMDiffStatsOut {
	return SBOMDiffStatsOut{
		Added:          s.AddedCount,
		Removed:        s.RemovedCount,
		Modified:       s.ModifiedCount,
		Unchanged:      s.UnchangedCount,
		MajorChanges:   s.MajorChanges,
		MinorChanges:   s.MinorChanges,
		PatchChanges:   s.PatchChanges,
		LicenseChanges: s.LicenseChanges,
	}
}

func convertComponent(c sbom.Component) ComponentOut {
	return ComponentOut{
		Name:     c.Name(),
		Version:  c.Version(),
		PURL:     c.PURL(),
		License:  c.License(),
		Language: c.Language(),
		Type:     c.Type(),
	}
}
