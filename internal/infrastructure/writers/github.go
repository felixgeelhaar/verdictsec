package writers

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// GitHubActionsWriter writes findings as GitHub Actions workflow commands.
// These create annotations in pull requests and commit views.
// Format: ::warning file={file},line={line},col={col},endColumn={endColumn}::{message}
type GitHubActionsWriter struct {
	out           io.Writer
	groupFindings bool
}

// GitHubActionsOption configures the GitHub Actions writer.
type GitHubActionsOption func(*GitHubActionsWriter)

// WithGitHubOutput sets the output writer.
func WithGitHubOutput(out io.Writer) GitHubActionsOption {
	return func(w *GitHubActionsWriter) {
		w.out = out
	}
}

// WithGroupFindings enables grouping of findings.
func WithGroupFindings(group bool) GitHubActionsOption {
	return func(w *GitHubActionsWriter) {
		w.groupFindings = group
	}
}

// NewGitHubActionsWriter creates a new GitHub Actions writer.
func NewGitHubActionsWriter(opts ...GitHubActionsOption) *GitHubActionsWriter {
	w := &GitHubActionsWriter{
		out:           os.Stdout,
		groupFindings: true,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// SetOutput sets the output destination.
func (w *GitHubActionsWriter) SetOutput(out io.Writer) {
	w.out = out
}

// WriteAssessment writes the assessment as GitHub Actions annotations.
func (w *GitHubActionsWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	findings := a.Findings()

	if len(findings) == 0 {
		return nil
	}

	if w.groupFindings {
		fmt.Fprintln(w.out, "::group::VerdictSec Security Findings")
	}

	for _, f := range findings {
		if err := w.writeAnnotation(f, result); err != nil {
			return err
		}
	}

	if w.groupFindings {
		fmt.Fprintln(w.out, "::endgroup::")
	}

	// Write summary
	w.writeSummary(a, result)

	return nil
}

// WriteSummary writes a brief summary.
func (w *GitHubActionsWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	return w.WriteAssessment(a, result)
}

// WriteProgress writes progress messages.
func (w *GitHubActionsWriter) WriteProgress(message string) error {
	// Use debug command for progress
	fmt.Fprintf(w.out, "::debug::%s\n", escapeMessage(message))
	return nil
}

// WriteError writes an error.
func (w *GitHubActionsWriter) WriteError(err error) error {
	fmt.Fprintf(w.out, "::error::%s\n", escapeMessage(err.Error()))
	return nil
}

// Flush ensures all output is written.
func (w *GitHubActionsWriter) Flush() error {
	return nil
}

// Close closes any resources.
func (w *GitHubActionsWriter) Close() error {
	if closer, ok := w.out.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// writeAnnotation writes a single finding as an annotation.
func (w *GitHubActionsWriter) writeAnnotation(f *finding.Finding, result services.EvaluationResult) error {
	level := w.severityToLevel(f.EffectiveSeverity())

	// Skip suppressed findings
	if isInSlice(f, result.Suppressed) {
		return nil
	}

	loc := f.Location()
	file := loc.File()
	line := loc.Line()
	col := loc.Column()
	endCol := loc.EndColumn()

	// Build annotation message
	message := fmt.Sprintf("[%s] %s: %s",
		f.EngineID(),
		f.RuleID(),
		f.Title(),
	)

	// Add metadata if available
	if f.CWEID() != "" {
		message += fmt.Sprintf(" (%s)", f.CWEID())
	}
	if f.CVEID() != "" {
		message += fmt.Sprintf(" [%s]", f.CVEID())
	}

	// Mark baseline findings
	if isInSlice(f, result.Existing) {
		message += " [baseline]"
	}

	// Build annotation command
	var annotation string
	if endCol > 0 && endCol > col {
		annotation = fmt.Sprintf("::%s file=%s,line=%d,col=%d,endColumn=%d::%s\n",
			level, file, line, col, endCol, escapeMessage(message))
	} else if col > 0 {
		annotation = fmt.Sprintf("::%s file=%s,line=%d,col=%d::%s\n",
			level, file, line, col, escapeMessage(message))
	} else {
		annotation = fmt.Sprintf("::%s file=%s,line=%d::%s\n",
			level, file, line, escapeMessage(message))
	}

	_, err := fmt.Fprint(w.out, annotation)
	return err
}

// writeSummary writes a summary notice.
func (w *GitHubActionsWriter) writeSummary(a *assessment.Assessment, result services.EvaluationResult) {
	summary := a.Summary()

	var parts []string
	if count := summary[finding.SeverityCritical]; count > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", count))
	}
	if count := summary[finding.SeverityHigh]; count > 0 {
		parts = append(parts, fmt.Sprintf("%d high", count))
	}
	if count := summary[finding.SeverityMedium]; count > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", count))
	}
	if count := summary[finding.SeverityLow]; count > 0 {
		parts = append(parts, fmt.Sprintf("%d low", count))
	}

	if len(parts) > 0 {
		summaryMsg := fmt.Sprintf("VerdictSec found %d findings: %s",
			len(a.Findings()), strings.Join(parts, ", "))

		level := "notice"
		if result.Decision == assessment.DecisionFail {
			level = "error"
		} else if result.Decision == assessment.DecisionWarn {
			level = "warning"
		}

		fmt.Fprintf(w.out, "::%s title=Security Scan Results::%s\n", level, escapeMessage(summaryMsg))
	}
}

// severityToLevel converts finding severity to GitHub Actions level.
func (w *GitHubActionsWriter) severityToLevel(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow:
		return "notice"
	default:
		return "notice"
	}
}

// escapeMessage escapes special characters for GitHub Actions.
// GitHub Actions uses %25, %0A, and %0D for %, \n, and \r.
func escapeMessage(msg string) string {
	msg = strings.ReplaceAll(msg, "%", "%25")
	msg = strings.ReplaceAll(msg, "\n", "%0A")
	msg = strings.ReplaceAll(msg, "\r", "%0D")
	msg = strings.ReplaceAll(msg, ":", "%3A")
	msg = strings.ReplaceAll(msg, ",", "%2C")
	return msg
}

// Ensure GitHubActionsWriter implements the interface.
var _ ports.ArtifactWriter = (*GitHubActionsWriter)(nil)
