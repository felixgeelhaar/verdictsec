package tui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// Colors matching fatih/color from console.go
var (
	ColorRed     = lipgloss.Color("9")  // color.FgRed
	ColorGreen   = lipgloss.Color("10") // color.FgGreen
	ColorYellow  = lipgloss.Color("11") // color.FgYellow
	ColorBlue    = lipgloss.Color("12") // color.FgBlue
	ColorMagenta = lipgloss.Color("13") // color.FgMagenta
	ColorCyan    = lipgloss.Color("14") // color.FgCyan
	ColorWhite   = lipgloss.Color("15")
	ColorGray    = lipgloss.Color("8") // color.Faint equivalent
)

// Status icons for findings
const (
	IconNew        = "●" // Filled circle for new findings
	IconBaseline   = "○" // Empty circle for baselined
	IconSuppressed = "◌" // Dotted circle for suppressed
)

// Styles contains all TUI styling definitions.
type Styles struct {
	// Severity styles
	Critical lipgloss.Style
	High     lipgloss.Style
	Medium   lipgloss.Style
	Low      lipgloss.Style
	Info     lipgloss.Style

	// Decision styles
	Pass  lipgloss.Style
	Warn  lipgloss.Style
	Fail  lipgloss.Style
	Error lipgloss.Style

	// Grade styles
	GradeA lipgloss.Style
	GradeB lipgloss.Style
	GradeC lipgloss.Style
	GradeD lipgloss.Style
	GradeF lipgloss.Style

	// Status styles
	New        lipgloss.Style
	Baseline   lipgloss.Style
	Suppressed lipgloss.Style

	// UI elements
	Title      lipgloss.Style
	Subtitle   lipgloss.Style
	Dim        lipgloss.Style
	Bold       lipgloss.Style
	Selected   lipgloss.Style
	StatusBar  lipgloss.Style

	// Borders and panels
	BorderFocused   lipgloss.Style
	BorderUnfocused lipgloss.Style
	Panel           lipgloss.Style
	Dialog          lipgloss.Style

	// Help
	HelpKey  lipgloss.Style
	HelpDesc lipgloss.Style
}

// NewStyles creates a new Styles instance.
func NewStyles(colorEnabled bool) Styles {
	if !colorEnabled {
		return newNoColorStyles()
	}

	return Styles{
		// Severity (matching console.go severityString)
		Critical: lipgloss.NewStyle().Foreground(ColorRed).Bold(true),
		High:     lipgloss.NewStyle().Foreground(ColorRed),
		Medium:   lipgloss.NewStyle().Foreground(ColorYellow),
		Low:      lipgloss.NewStyle().Foreground(ColorBlue),
		Info:     lipgloss.NewStyle().Foreground(ColorGray),

		// Decision (matching console.go writeDecision)
		Pass:  lipgloss.NewStyle().Foreground(ColorGreen).Bold(true),
		Warn:  lipgloss.NewStyle().Foreground(ColorYellow).Bold(true),
		Fail:  lipgloss.NewStyle().Foreground(ColorRed).Bold(true),
		Error: lipgloss.NewStyle().Foreground(ColorRed),

		// Grade (matching console.go gradeString)
		GradeA: lipgloss.NewStyle().Foreground(ColorGreen).Bold(true),
		GradeB: lipgloss.NewStyle().Foreground(ColorGreen),
		GradeC: lipgloss.NewStyle().Foreground(ColorYellow),
		GradeD: lipgloss.NewStyle().Foreground(ColorYellow),
		GradeF: lipgloss.NewStyle().Foreground(ColorRed).Bold(true),

		// Status indicators
		New:        lipgloss.NewStyle().Foreground(ColorRed),
		Baseline:   lipgloss.NewStyle().Foreground(ColorGray),
		Suppressed: lipgloss.NewStyle().Foreground(ColorGray).Italic(true),

		// UI
		Title:     lipgloss.NewStyle().Bold(true),
		Subtitle:  lipgloss.NewStyle().Foreground(ColorCyan),
		Dim:       lipgloss.NewStyle().Foreground(ColorGray),
		Bold:      lipgloss.NewStyle().Bold(true),
		Selected:  lipgloss.NewStyle().Background(lipgloss.Color("236")).Bold(true),
		StatusBar: lipgloss.NewStyle().Foreground(ColorGray),

		// Borders
		BorderFocused:   lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(ColorCyan),
		BorderUnfocused: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(ColorGray),
		Panel:           lipgloss.NewStyle().Padding(0, 1),
		Dialog:          lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(ColorYellow).Padding(1, 2),

		// Help
		HelpKey:  lipgloss.NewStyle().Foreground(ColorCyan),
		HelpDesc: lipgloss.NewStyle().Foreground(ColorGray),
	}
}

// newNoColorStyles creates styles without colors for --no-color mode.
func newNoColorStyles() Styles {
	plain := lipgloss.NewStyle()

	return Styles{
		Critical:        plain,
		High:            plain,
		Medium:          plain,
		Low:             plain,
		Info:            plain,
		Pass:            plain,
		Warn:            plain,
		Fail:            plain,
		Error:           plain,
		GradeA:          plain,
		GradeB:          plain,
		GradeC:          plain,
		GradeD:          plain,
		GradeF:          plain,
		New:             plain,
		Baseline:        plain,
		Suppressed:      plain,
		Title:           plain.Bold(true),
		Subtitle:        plain,
		Dim:             plain,
		Bold:            plain.Bold(true),
		Selected:        plain.Bold(true),
		StatusBar:       plain,
		BorderFocused:   lipgloss.NewStyle().Border(lipgloss.RoundedBorder()),
		BorderUnfocused: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()),
		Panel:           lipgloss.NewStyle().Padding(0, 1),
		Dialog:          lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).Padding(1, 2),
		HelpKey:         plain,
		HelpDesc:        plain,
	}
}

// SeverityStyle returns the appropriate style for a severity level.
func (s Styles) SeverityStyle(sev finding.Severity) lipgloss.Style {
	switch sev {
	case finding.SeverityCritical:
		return s.Critical
	case finding.SeverityHigh:
		return s.High
	case finding.SeverityMedium:
		return s.Medium
	case finding.SeverityLow:
		return s.Low
	default:
		return s.Info
	}
}

// DecisionStyle returns the appropriate style for a decision.
func (s Styles) DecisionStyle(d assessment.Decision) lipgloss.Style {
	switch d {
	case assessment.DecisionPass:
		return s.Pass
	case assessment.DecisionWarn:
		return s.Warn
	case assessment.DecisionFail:
		return s.Fail
	default:
		return s.Error
	}
}

// GradeStyle returns the appropriate style for a grade.
func (s Styles) GradeStyle(g services.Grade) lipgloss.Style {
	switch g {
	case services.GradeA:
		return s.GradeA
	case services.GradeB:
		return s.GradeB
	case services.GradeC:
		return s.GradeC
	case services.GradeD:
		return s.GradeD
	default:
		return s.GradeF
	}
}

// StatusStyle returns the appropriate style for a finding status.
func (s Styles) StatusStyle(status string) lipgloss.Style {
	switch status {
	case "new":
		return s.New
	case "baseline":
		return s.Baseline
	case "suppressed":
		return s.Suppressed
	default:
		return s.Dim
	}
}

// StatusIcon returns the icon for a finding status.
func StatusIcon(status string) string {
	switch status {
	case "new":
		return IconNew
	case "baseline":
		return IconBaseline
	case "suppressed":
		return IconSuppressed
	default:
		return IconNew
	}
}
