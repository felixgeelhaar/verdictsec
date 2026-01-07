package writers

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/pkg/redact"
)

// ConsoleWriter writes human-readable output to the console.
type ConsoleWriter struct {
	out       io.Writer
	err       io.Writer
	color     bool
	verbosity ports.Verbosity
	redactor  *redact.Redactor

	// Color functions
	red     func(a ...interface{}) string
	green   func(a ...interface{}) string
	yellow  func(a ...interface{}) string
	blue    func(a ...interface{}) string
	magenta func(a ...interface{}) string
	cyan    func(a ...interface{}) string
	bold    func(a ...interface{}) string
	dim     func(a ...interface{}) string
}

// NewConsoleWriter creates a new console writer.
func NewConsoleWriter(opts ...ConsoleOption) *ConsoleWriter {
	w := &ConsoleWriter{
		out:       os.Stdout,
		err:       os.Stderr,
		color:     true,
		verbosity: ports.VerbosityNormal,
		redactor:  redact.New(redact.WithPartialDisplay(4, 4)),
	}

	for _, opt := range opts {
		opt(w)
	}

	w.initColors()
	return w
}

// ConsoleOption configures the console writer.
type ConsoleOption func(*ConsoleWriter)

// WithOutput sets the output writer.
func WithOutput(out io.Writer) ConsoleOption {
	return func(w *ConsoleWriter) {
		w.out = out
	}
}

// WithErrorOutput sets the error output writer.
func WithErrorOutput(err io.Writer) ConsoleOption {
	return func(w *ConsoleWriter) {
		w.err = err
	}
}

// WithColor enables or disables colored output.
func WithColor(enabled bool) ConsoleOption {
	return func(w *ConsoleWriter) {
		w.color = enabled
	}
}

// WithVerbosity sets the verbosity level.
func WithVerbosity(v ports.Verbosity) ConsoleOption {
	return func(w *ConsoleWriter) {
		w.verbosity = v
	}
}

// initColors initializes color functions based on color setting.
func (w *ConsoleWriter) initColors() {
	if w.color {
		w.red = color.New(color.FgRed).SprintFunc()
		w.green = color.New(color.FgGreen).SprintFunc()
		w.yellow = color.New(color.FgYellow).SprintFunc()
		w.blue = color.New(color.FgBlue).SprintFunc()
		w.magenta = color.New(color.FgMagenta).SprintFunc()
		w.cyan = color.New(color.FgCyan).SprintFunc()
		w.bold = color.New(color.Bold).SprintFunc()
		w.dim = color.New(color.Faint).SprintFunc()
	} else {
		noColor := func(a ...interface{}) string { return fmt.Sprint(a...) }
		w.red = noColor
		w.green = noColor
		w.yellow = noColor
		w.blue = noColor
		w.magenta = noColor
		w.cyan = noColor
		w.bold = noColor
		w.dim = noColor
	}
}

// SetColor enables or disables colored output.
func (w *ConsoleWriter) SetColor(enabled bool) {
	w.color = enabled
	w.initColors()
}

// SetVerbosity sets the output detail level.
func (w *ConsoleWriter) SetVerbosity(v ports.Verbosity) {
	w.verbosity = v
}

// WriteAssessment writes the full assessment result.
func (w *ConsoleWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	// Write header
	w.writeHeader(a)

	// Write findings grouped by severity
	if len(a.Findings()) > 0 {
		w.writeFindings(a.Findings(), result)
	}

	// Write summary
	w.writeSummary(a, result)

	// Write decision
	w.writeDecision(result)

	return nil
}

// WriteSummary writes a brief summary.
func (w *ConsoleWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	w.writeSummary(a, result)
	w.writeDecision(result)
	return nil
}

// WriteProgress writes a progress message.
func (w *ConsoleWriter) WriteProgress(message string) error {
	if w.verbosity == ports.VerbosityQuiet {
		return nil
	}

	fmt.Fprintf(w.out, "%s %s\n", w.dim(">>>"), message)
	return nil
}

// WriteError writes an error message.
func (w *ConsoleWriter) WriteError(err error) error {
	fmt.Fprintf(w.err, "%s %s\n", w.red("ERROR:"), err.Error())
	return nil
}

// Flush ensures all output is written.
func (w *ConsoleWriter) Flush() error {
	return nil
}

// writeHeader writes the assessment header.
func (w *ConsoleWriter) writeHeader(a *assessment.Assessment) {
	fmt.Fprintln(w.out)
	fmt.Fprintf(w.out, "%s\n", w.bold("VerdictSec Security Assessment"))
	fmt.Fprintf(w.out, "%s\n", strings.Repeat("=", 40))
	fmt.Fprintf(w.out, "Target: %s\n", w.cyan(a.Target()))
	fmt.Fprintf(w.out, "Duration: %s\n", a.Duration().Round(1e6))

	if w.verbosity == ports.VerbosityVerbose || w.verbosity == ports.VerbosityDebug {
		fmt.Fprintf(w.out, "Assessment ID: %s\n", a.ID())
		fmt.Fprintf(w.out, "Engines Run: %d (Success: %d, Failed: %d)\n",
			len(a.EngineRuns()), a.SuccessfulEngineRuns(), a.FailedEngineRuns())
	}
	fmt.Fprintln(w.out)
}

// writeFindings writes all findings.
func (w *ConsoleWriter) writeFindings(findings []*finding.Finding, result services.EvaluationResult) {
	if w.verbosity == ports.VerbosityQuiet {
		return
	}

	fmt.Fprintf(w.out, "%s\n", w.bold("Findings"))
	fmt.Fprintf(w.out, "%s\n", strings.Repeat("-", 40))

	// Group by severity
	bySeverity := make(map[finding.Severity][]*finding.Finding)
	for _, f := range findings {
		sev := f.EffectiveSeverity()
		bySeverity[sev] = append(bySeverity[sev], f)
	}

	// Print in severity order (Critical -> Low)
	severities := []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
	}

	for _, sev := range severities {
		if fs, ok := bySeverity[sev]; ok {
			for _, f := range fs {
				w.writeFinding(f, result)
			}
		}
	}

	fmt.Fprintln(w.out)
}

// writeFinding writes a single finding.
func (w *ConsoleWriter) writeFinding(f *finding.Finding, result services.EvaluationResult) {
	// Severity badge
	sevStr := w.severityString(f.EffectiveSeverity())

	// Status indicator
	status := ""
	if isInSlice(f, result.Existing) {
		status = w.dim(" (baseline)")
	} else if isInSlice(f, result.Suppressed) {
		status = w.dim(" (suppressed)")
	}

	// Title line
	fmt.Fprintf(w.out, "\n%s %s%s\n", sevStr, w.bold(f.Title()), status)

	// Location
	loc := f.Location()
	fmt.Fprintf(w.out, "  %s %s:%d\n", w.dim("Location:"), loc.File(), loc.Line())

	// Rule info
	fmt.Fprintf(w.out, "  %s %s [%s]\n", w.dim("Rule:"), f.RuleID(), f.EngineID())

	// Fingerprint (short)
	fmt.Fprintf(w.out, "  %s %s\n", w.dim("Fingerprint:"), f.Fingerprint().Short())

	// Verbose details
	if w.verbosity == ports.VerbosityVerbose || w.verbosity == ports.VerbosityDebug {
		if f.Description() != "" {
			fmt.Fprintf(w.out, "  %s %s\n", w.dim("Description:"), f.Description())
		}
		if f.HasCWE() {
			fmt.Fprintf(w.out, "  %s %s\n", w.dim("CWE:"), f.CWEID())
		}
		if f.HasCVE() {
			fmt.Fprintf(w.out, "  %s %s\n", w.dim("CVE:"), f.CVEID())
		}
		if f.HasFix() {
			fmt.Fprintf(w.out, "  %s %s\n", w.dim("Fix Version:"), f.FixVersion())
		}

		// Redact secret evidence
		metadata := f.Metadata()
		if metadata != nil {
			if secret, ok := metadata["secret"]; ok {
				if str, ok := secret.(string); ok {
					fmt.Fprintf(w.out, "  %s %s\n", w.dim("Secret:"), w.redactor.Redact(str))
				}
			}
		}
	}
}

// writeSummary writes the assessment summary.
func (w *ConsoleWriter) writeSummary(a *assessment.Assessment, result services.EvaluationResult) {
	summary := a.Summary()

	fmt.Fprintf(w.out, "%s\n", w.bold("Summary"))
	fmt.Fprintf(w.out, "%s\n", strings.Repeat("-", 40))
	fmt.Fprintf(w.out, "Total Findings: %d\n", a.FindingCount())

	if a.FindingCount() > 0 {
		fmt.Fprintf(w.out, "  %s: %d\n", w.red("Critical"), summary[finding.SeverityCritical])
		fmt.Fprintf(w.out, "  %s: %d\n", w.red("High"), summary[finding.SeverityHigh])
		fmt.Fprintf(w.out, "  %s: %d\n", w.yellow("Medium"), summary[finding.SeverityMedium])
		fmt.Fprintf(w.out, "  %s: %d\n", w.blue("Low"), summary[finding.SeverityLow])
	}

	if len(result.NewFindings) > 0 || len(result.Existing) > 0 || len(result.Suppressed) > 0 || len(result.InlineSuppressed) > 0 {
		fmt.Fprintln(w.out)
		fmt.Fprintf(w.out, "New: %d, Baseline: %d, Suppressed: %d",
			len(result.NewFindings), len(result.Existing), len(result.Suppressed))
		if len(result.InlineSuppressed) > 0 {
			fmt.Fprintf(w.out, ", Inline: %d", len(result.InlineSuppressed))
		}
		fmt.Fprintln(w.out)
	}

	fmt.Fprintln(w.out)

	// Write security score
	w.writeScore(result.Score)
}

// writeScore writes the security score with colored grade.
func (w *ConsoleWriter) writeScore(score services.Score) {
	fmt.Fprintf(w.out, "%s\n", w.bold("Security Score"))
	fmt.Fprintf(w.out, "%s\n", strings.Repeat("-", 40))

	// Format score with colored grade
	gradeStr := w.gradeString(score.Grade)
	fmt.Fprintf(w.out, "%s: %d/100 (%s)\n", w.bold("Score"), score.Value, gradeStr)

	// Show factors if there are any
	if len(score.Factors) > 0 && w.verbosity != ports.VerbosityQuiet {
		fmt.Fprintln(w.out)
		for _, factor := range score.Factors {
			sign := "+"
			colorFn := w.green
			if factor.Points < 0 {
				sign = ""
				colorFn = w.red
			}
			fmt.Fprintf(w.out, "  %s: %s\n",
				colorFn(fmt.Sprintf("%s%d", sign, factor.Points)),
				factor.Reason)
		}
	}

	fmt.Fprintln(w.out)
}

// gradeString returns a colored grade string.
func (w *ConsoleWriter) gradeString(grade services.Grade) string {
	switch grade {
	case services.GradeA:
		return w.green(string(grade))
	case services.GradeB:
		return w.green(string(grade))
	case services.GradeC:
		return w.yellow(string(grade))
	case services.GradeD:
		return w.yellow(string(grade))
	case services.GradeF:
		return w.red(string(grade))
	default:
		return string(grade)
	}
}

// writeDecision writes the final decision.
func (w *ConsoleWriter) writeDecision(result services.EvaluationResult) {
	fmt.Fprintf(w.out, "%s\n", strings.Repeat("=", 40))

	switch result.Decision {
	case assessment.DecisionPass:
		fmt.Fprintf(w.out, "Result: %s\n", w.green("PASS"))
	case assessment.DecisionWarn:
		fmt.Fprintf(w.out, "Result: %s\n", w.yellow("WARN"))
	case assessment.DecisionFail:
		fmt.Fprintf(w.out, "Result: %s\n", w.red("FAIL"))
	default:
		fmt.Fprintf(w.out, "Result: %s\n", "UNKNOWN")
	}

	if w.verbosity != ports.VerbosityQuiet && len(result.Reasons) > 0 {
		for _, reason := range result.Reasons {
			fmt.Fprintf(w.out, "  - %s\n", reason)
		}
	}

	fmt.Fprintln(w.out)
}

// severityString returns a colored severity string.
func (w *ConsoleWriter) severityString(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return w.red("[CRITICAL]")
	case finding.SeverityHigh:
		return w.red("[HIGH]")
	case finding.SeverityMedium:
		return w.yellow("[MEDIUM]")
	case finding.SeverityLow:
		return w.blue("[LOW]")
	default:
		return "[UNKNOWN]"
	}
}

// isInSlice checks if a finding is in a slice.
func isInSlice(f *finding.Finding, slice []*finding.Finding) bool {
	for _, item := range slice {
		if item.ID() == f.ID() {
			return true
		}
	}
	return false
}

// Ensure ConsoleWriter implements the interface.
var _ ports.ConsoleWriter = (*ConsoleWriter)(nil)
