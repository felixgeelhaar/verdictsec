package writers

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/sbom"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// ANSI color codes for SBOM diff output.
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorMagenta = "\033[35m"
	colorBold    = "\033[1m"
)

// SBOMDiffConsoleWriter writes SBOM diffs to console with colors.
type SBOMDiffConsoleWriter struct {
	w      io.Writer
	colors bool
}

// NewSBOMDiffConsoleWriter creates a new console writer for SBOM diffs.
func NewSBOMDiffConsoleWriter(w io.Writer, colors bool) *SBOMDiffConsoleWriter {
	return &SBOMDiffConsoleWriter{
		w:      w,
		colors: colors,
	}
}

// Write outputs the SBOM diff to console.
func (wr *SBOMDiffConsoleWriter) Write(result services.SBOMDiffResult) error {
	stats := result.Stats()

	// Header
	wr.printHeader("SBOM Diff")

	// Summary
	if result.Base != nil && result.Target != nil {
		fmt.Fprintf(wr.w, "\n%s %s → %s\n",
			wr.colorize("Base:", colorCyan),
			result.Base.Source(),
			result.Target.Source())
		fmt.Fprintf(wr.w, "%s %d → %d components\n",
			wr.colorize("Count:", colorCyan),
			result.TotalBase(),
			result.TotalTarget())
	}

	// Stats summary
	fmt.Fprintf(wr.w, "\n%s\n", wr.colorize("Summary:", colorBold))
	fmt.Fprintf(wr.w, "  %s %d added\n", wr.colorize("+", colorGreen), stats.AddedCount)
	fmt.Fprintf(wr.w, "  %s %d removed\n", wr.colorize("-", colorRed), stats.RemovedCount)
	fmt.Fprintf(wr.w, "  %s %d modified\n", wr.colorize("~", colorYellow), stats.ModifiedCount)
	if stats.MajorChanges > 0 {
		fmt.Fprintf(wr.w, "    %s %d major version changes\n", wr.colorize("↑", colorRed), stats.MajorChanges)
	}
	if stats.MinorChanges > 0 {
		fmt.Fprintf(wr.w, "    %s %d minor version changes\n", wr.colorize("↗", colorYellow), stats.MinorChanges)
	}
	if stats.PatchChanges > 0 {
		fmt.Fprintf(wr.w, "    %s %d patch version changes\n", wr.colorize("→", colorCyan), stats.PatchChanges)
	}
	if stats.LicenseChanges > 0 {
		fmt.Fprintf(wr.w, "    %s %d license changes\n", wr.colorize("📜", colorMagenta), stats.LicenseChanges)
	}
	fmt.Fprintf(wr.w, "  = %d unchanged\n", stats.UnchangedCount)

	// Added components
	if len(result.Added) > 0 {
		fmt.Fprintf(wr.w, "\n%s\n", wr.colorize("Added Components:", colorGreen))
		wr.printComponents(result.Added, "+", colorGreen)
	}

	// Removed components
	if len(result.Removed) > 0 {
		fmt.Fprintf(wr.w, "\n%s\n", wr.colorize("Removed Components:", colorRed))
		wr.printComponents(result.Removed, "-", colorRed)
	}

	// Modified components
	if len(result.Modified) > 0 {
		fmt.Fprintf(wr.w, "\n%s\n", wr.colorize("Modified Components:", colorYellow))
		wr.printModified(result.Modified)
	}

	fmt.Fprintln(wr.w)
	return nil
}

func (wr *SBOMDiffConsoleWriter) printHeader(title string) {
	line := strings.Repeat("─", 50)
	fmt.Fprintf(wr.w, "%s\n", wr.colorize(line, colorCyan))
	fmt.Fprintf(wr.w, "%s\n", wr.colorize(title, colorBold))
	fmt.Fprintf(wr.w, "%s\n", wr.colorize(line, colorCyan))
}

func (wr *SBOMDiffConsoleWriter) printComponents(components []sbom.Component, prefix string, color string) {
	// Sort by name
	sorted := make([]sbom.Component, len(components))
	copy(sorted, components)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name() < sorted[j].Name()
	})

	for _, c := range sorted {
		name := c.String()
		if c.License() != "" {
			name = fmt.Sprintf("%s (%s)", name, c.License())
		}
		fmt.Fprintf(wr.w, "  %s %s\n", wr.colorize(prefix, color), name)
	}
}

func (wr *SBOMDiffConsoleWriter) printModified(diffs []services.ComponentDiff) {
	// Sort by name
	sorted := make([]services.ComponentDiff, len(diffs))
	copy(sorted, diffs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Target.Name() < sorted[j].Target.Name()
	})

	for _, d := range sorted {
		// Version change indicator
		var changeIndicator string
		var changeColor string
		switch d.VersionChange {
		case sbom.VersionMajor:
			changeIndicator = "↑ MAJOR"
			changeColor = colorRed
		case sbom.VersionMinor:
			changeIndicator = "↗ minor"
			changeColor = colorYellow
		case sbom.VersionPatch:
			changeIndicator = "→ patch"
			changeColor = colorCyan
		default:
			changeIndicator = "~ changed"
			changeColor = colorYellow
		}

		fmt.Fprintf(wr.w, "  %s %s: %s → %s",
			wr.colorize("~", colorYellow),
			d.Target.Name(),
			wr.colorize(d.Base.Version(), colorRed),
			wr.colorize(d.Target.Version(), colorGreen))

		fmt.Fprintf(wr.w, " [%s]", wr.colorize(changeIndicator, changeColor))

		if d.LicenseChange {
			fmt.Fprintf(wr.w, " %s",
				wr.colorize(fmt.Sprintf("license: %s → %s", d.Base.License(), d.Target.License()), colorMagenta))
		}
		fmt.Fprintln(wr.w)
	}
}

func (wr *SBOMDiffConsoleWriter) colorize(s, color string) string {
	if !wr.colors {
		return s
	}
	return color + s + colorReset
}

// SBOMDiffJSONWriter writes SBOM diffs as JSON.
type SBOMDiffJSONWriter struct {
	w      io.Writer
	pretty bool
}

// NewSBOMDiffJSONWriter creates a new JSON writer for SBOM diffs.
func NewSBOMDiffJSONWriter(w io.Writer, pretty bool) *SBOMDiffJSONWriter {
	return &SBOMDiffJSONWriter{
		w:      w,
		pretty: pretty,
	}
}

// Write outputs the SBOM diff as JSON.
func (wr *SBOMDiffJSONWriter) Write(result services.SBOMDiffResult) error {
	output := ports.ConvertToOutput(result)

	encoder := json.NewEncoder(wr.w)
	if wr.pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(output)
}

// SBOMDiffMarkdownWriter writes SBOM diffs as Markdown.
type SBOMDiffMarkdownWriter struct {
	w io.Writer
}

// NewSBOMDiffMarkdownWriter creates a new Markdown writer for SBOM diffs.
func NewSBOMDiffMarkdownWriter(w io.Writer) *SBOMDiffMarkdownWriter {
	return &SBOMDiffMarkdownWriter{w: w}
}

// Write outputs the SBOM diff as Markdown.
func (wr *SBOMDiffMarkdownWriter) Write(result services.SBOMDiffResult) error {
	stats := result.Stats()

	fmt.Fprintln(wr.w, "# SBOM Diff Report")
	fmt.Fprintln(wr.w)

	// Summary table
	fmt.Fprintln(wr.w, "## Summary")
	fmt.Fprintln(wr.w)
	fmt.Fprintln(wr.w, "| Metric | Count |")
	fmt.Fprintln(wr.w, "|--------|-------|")
	fmt.Fprintf(wr.w, "| ➕ Added | %d |\n", stats.AddedCount)
	fmt.Fprintf(wr.w, "| ➖ Removed | %d |\n", stats.RemovedCount)
	fmt.Fprintf(wr.w, "| ✏️ Modified | %d |\n", stats.ModifiedCount)
	fmt.Fprintf(wr.w, "| ⏸️ Unchanged | %d |\n", stats.UnchangedCount)
	fmt.Fprintln(wr.w)

	if stats.ModifiedCount > 0 {
		fmt.Fprintln(wr.w, "### Version Changes")
		fmt.Fprintln(wr.w)
		fmt.Fprintln(wr.w, "| Type | Count |")
		fmt.Fprintln(wr.w, "|------|-------|")
		fmt.Fprintf(wr.w, "| 🔴 Major | %d |\n", stats.MajorChanges)
		fmt.Fprintf(wr.w, "| 🟡 Minor | %d |\n", stats.MinorChanges)
		fmt.Fprintf(wr.w, "| 🟢 Patch | %d |\n", stats.PatchChanges)
		fmt.Fprintf(wr.w, "| 📜 License | %d |\n", stats.LicenseChanges)
		fmt.Fprintln(wr.w)
	}

	// Added components
	if len(result.Added) > 0 {
		fmt.Fprintln(wr.w, "## ➕ Added Components")
		fmt.Fprintln(wr.w)
		fmt.Fprintln(wr.w, "| Component | Version | License |")
		fmt.Fprintln(wr.w, "|-----------|---------|---------|")
		for _, c := range result.Added {
			fmt.Fprintf(wr.w, "| %s | %s | %s |\n", c.Name(), c.Version(), c.License())
		}
		fmt.Fprintln(wr.w)
	}

	// Removed components
	if len(result.Removed) > 0 {
		fmt.Fprintln(wr.w, "## ➖ Removed Components")
		fmt.Fprintln(wr.w)
		fmt.Fprintln(wr.w, "| Component | Version | License |")
		fmt.Fprintln(wr.w, "|-----------|---------|---------|")
		for _, c := range result.Removed {
			fmt.Fprintf(wr.w, "| %s | %s | %s |\n", c.Name(), c.Version(), c.License())
		}
		fmt.Fprintln(wr.w)
	}

	// Modified components
	if len(result.Modified) > 0 {
		fmt.Fprintln(wr.w, "## ✏️ Modified Components")
		fmt.Fprintln(wr.w)
		fmt.Fprintln(wr.w, "| Component | Old Version | New Version | Change |")
		fmt.Fprintln(wr.w, "|-----------|-------------|-------------|--------|")
		for _, d := range result.Modified {
			changeType := string(d.VersionChange)
			if d.LicenseChange {
				changeType += " + license"
			}
			fmt.Fprintf(wr.w, "| %s | %s | %s | %s |\n",
				d.Target.Name(),
				d.Base.Version(),
				d.Target.Version(),
				changeType)
		}
		fmt.Fprintln(wr.w)
	}

	return nil
}

// SBOMDiffWriterFactory creates SBOM diff writers.
type SBOMDiffWriterFactory struct{}

// NewSBOMDiffWriterFactory creates a new factory.
func NewSBOMDiffWriterFactory() *SBOMDiffWriterFactory {
	return &SBOMDiffWriterFactory{}
}

// Console creates a console writer.
func (f *SBOMDiffWriterFactory) Console(w io.Writer, colors bool) ports.SBOMDiffWriter {
	return NewSBOMDiffConsoleWriter(w, colors)
}

// JSON creates a JSON writer.
func (f *SBOMDiffWriterFactory) JSON(w io.Writer, pretty bool) ports.SBOMDiffWriter {
	return NewSBOMDiffJSONWriter(w, pretty)
}

// Markdown creates a Markdown writer.
func (f *SBOMDiffWriterFactory) Markdown(w io.Writer) ports.SBOMDiffWriter {
	return NewSBOMDiffMarkdownWriter(w)
}
