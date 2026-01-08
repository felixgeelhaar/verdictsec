package writers

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/providers"
)

// PRWriter posts findings as PR/MR review comments using any provider.
type PRWriter struct {
	provider providers.PRProvider
	prFiles  map[string]bool
	ctx      context.Context

	// Fallback console writer for progress messages
	console *ConsoleWriter
}

// NewPRWriter creates a new PR writer for the given provider.
func NewPRWriter(ctx context.Context, provider providers.PRProvider) (*PRWriter, error) {
	writer := &PRWriter{
		provider: provider,
		prFiles:  make(map[string]bool),
		ctx:      ctx,
		console:  NewConsoleWriter(),
	}

	// Load the list of files changed in the PR
	files, err := provider.GetChangedFiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get changed files: %w", err)
	}

	for _, f := range files {
		writer.prFiles[f] = true
	}

	return writer, nil
}

// WriteAssessment posts findings as a PR review.
func (w *PRWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	// Filter findings to only those in PR files
	allFindings := a.Findings()
	prFindings := w.filterFindings(allFindings)

	// Build review comments
	comments := w.buildComments(prFindings)
	summary := w.buildSummary(prFindings)

	// Determine if we should request changes
	requestChanges := hasCriticalOrHighFindings(prFindings)

	// Submit the review
	if err := w.provider.CreateReview(w.ctx, comments, summary, requestChanges); err != nil {
		return fmt.Errorf("failed to create review: %w", err)
	}

	// Log progress
	_ = w.console.WriteProgress(fmt.Sprintf("[%s] Posted %d findings to PR #%d (%d total findings, %d in PR files)",
		w.provider.Name(), len(prFindings), w.provider.PRNumber(), len(allFindings), len(prFindings)))

	return nil
}

// WriteSummary posts a summary comment to the PR.
func (w *PRWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	prFindings := w.filterFindings(a.Findings())
	summary := w.buildSummary(prFindings)

	if err := w.provider.PostSummary(w.ctx, summary); err != nil {
		return fmt.Errorf("failed to post summary: %w", err)
	}

	return nil
}

// WriteProgress writes a progress message to console.
func (w *PRWriter) WriteProgress(message string) error {
	return w.console.WriteProgress(message)
}

// WriteError writes an error message to console.
func (w *PRWriter) WriteError(err error) error {
	return w.console.WriteError(err)
}

// Flush ensures all output is written.
func (w *PRWriter) Flush() error {
	return nil
}

// filterFindings filters findings to only those in files changed by the PR.
func (w *PRWriter) filterFindings(findings []*finding.Finding) []*finding.Finding {
	var filtered []*finding.Finding
	for _, f := range findings {
		filePath := normalizeFindingPath(f.Location().File())
		if w.prFiles[filePath] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// buildComments creates review comments from findings.
func (w *PRWriter) buildComments(findings []*finding.Finding) []providers.ReviewComment {
	comments := make([]providers.ReviewComment, 0, len(findings))
	for _, f := range findings {
		comment := providers.ReviewComment{
			Path:     normalizeFindingPath(f.Location().File()),
			Line:     f.Location().Line(),
			Side:     "RIGHT",
			Body:     w.formatFindingComment(f),
			Severity: f.EffectiveSeverity(),
		}
		comments = append(comments, comment)
	}
	return comments
}

// formatFindingComment formats a finding as a markdown comment.
func (w *PRWriter) formatFindingComment(f *finding.Finding) string {
	var sb strings.Builder

	// Severity emoji
	emoji := severityEmojiForFinding(f.EffectiveSeverity())

	// Header
	sb.WriteString(fmt.Sprintf("## %s **%s**\n\n", emoji, f.Title()))

	// Metadata
	sb.WriteString(fmt.Sprintf("**Severity:** %s | **Engine:** %s",
		f.EffectiveSeverity().String(), f.EngineID()))

	if f.HasCWE() {
		sb.WriteString(fmt.Sprintf(" | **CWE:** [%s](https://cwe.mitre.org/data/definitions/%s.html)",
			f.CWEID(), strings.TrimPrefix(f.CWEID(), "CWE-")))
	}
	sb.WriteString("\n\n")

	// Description
	if f.Description() != "" {
		sb.WriteString(f.Description())
		sb.WriteString("\n\n")
	}

	// Rule info
	sb.WriteString(fmt.Sprintf("**Rule:** `%s`\n", f.RuleID()))

	// CVE if present
	if f.HasCVE() {
		sb.WriteString(fmt.Sprintf("\n**CVE:** [%s](https://nvd.nist.gov/vuln/detail/%s)\n",
			f.CVEID(), f.CVEID()))
	}

	// Fix version if present
	if f.HasFix() {
		sb.WriteString(fmt.Sprintf("\n**Fix Available:** Upgrade to version %s\n", f.FixVersion()))
	}

	// Remediation hint
	sb.WriteString("\n<details>\n<summary>Remediation</summary>\n\n")
	sb.WriteString(getRemediationHint(f))
	sb.WriteString("\n</details>\n")

	return sb.String()
}

// buildSummary creates the review summary body.
func (w *PRWriter) buildSummary(findings []*finding.Finding) string {
	if len(findings) == 0 {
		return "## VerdictSec Security Scan\n\nNo security findings detected in this PR."
	}

	var sb strings.Builder

	// Count by severity
	critical, high, medium, low := 0, 0, 0, 0
	for _, f := range findings {
		switch f.EffectiveSeverity() {
		case finding.SeverityCritical:
			critical++
		case finding.SeverityHigh:
			high++
		case finding.SeverityMedium:
			medium++
		case finding.SeverityLow:
			low++
		}
	}

	// Header
	if critical > 0 || high > 0 {
		sb.WriteString("## VerdictSec Security Scan - Action Required\n\n")
	} else {
		sb.WriteString("## VerdictSec Security Scan - Review Recommended\n\n")
	}

	// Summary table
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	if critical > 0 {
		sb.WriteString(fmt.Sprintf("| Critical | %d |\n", critical))
	}
	if high > 0 {
		sb.WriteString(fmt.Sprintf("| High | %d |\n", high))
	}
	if medium > 0 {
		sb.WriteString(fmt.Sprintf("| Medium | %d |\n", medium))
	}
	if low > 0 {
		sb.WriteString(fmt.Sprintf("| Low | %d |\n", low))
	}
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n", len(findings)))
	sb.WriteString("\n")

	// Action items
	if critical > 0 {
		sb.WriteString("### Critical findings must be resolved before merge\n\n")
	} else if high > 0 {
		sb.WriteString("### High severity findings should be addressed\n\n")
	}

	sb.WriteString("Please review the inline comments for detailed findings and remediation guidance.\n")

	return sb.String()
}

// normalizeFindingPath normalizes a file path to match provider format.
func normalizeFindingPath(path string) string {
	// Remove leading ./ if present
	path = strings.TrimPrefix(path, "./")
	// Convert to forward slashes
	path = filepath.ToSlash(path)
	return path
}

// severityEmojiForFinding returns an emoji for a severity level.
func severityEmojiForFinding(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return "🔴"
	case finding.SeverityHigh:
		return "🟠"
	case finding.SeverityMedium:
		return "🟡"
	case finding.SeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}

// hasCriticalOrHighFindings returns true if any finding is critical or high severity.
func hasCriticalOrHighFindings(findings []*finding.Finding) bool {
	for _, f := range findings {
		sev := f.EffectiveSeverity()
		if sev == finding.SeverityCritical || sev == finding.SeverityHigh {
			return true
		}
	}
	return false
}

// getRemediationHint returns a remediation hint for a finding.
func getRemediationHint(f *finding.Finding) string {
	ruleID := f.RuleID()

	switch {
	case strings.HasPrefix(ruleID, "G101"):
		return "Remove hard-coded credentials and use environment variables or a secret management system."
	case strings.HasPrefix(ruleID, "G102"):
		return "Avoid binding to all network interfaces (0.0.0.0). Bind to specific interfaces instead."
	case strings.HasPrefix(ruleID, "G103"):
		return "Audit the use of unsafe operations carefully and document their necessity."
	case strings.HasPrefix(ruleID, "G104"):
		return "Handle all errors explicitly. Don't ignore error return values."
	case strings.HasPrefix(ruleID, "G107"):
		return "Validate and sanitize URLs before making HTTP requests to prevent SSRF attacks."
	case strings.HasPrefix(ruleID, "G201"), strings.HasPrefix(ruleID, "G202"):
		return "Use parameterized queries instead of string concatenation to prevent SQL injection."
	case strings.HasPrefix(ruleID, "G203"), strings.HasPrefix(ruleID, "G204"):
		return "Sanitize user input before using in HTML templates or shell commands."
	case strings.HasPrefix(ruleID, "G301"), strings.HasPrefix(ruleID, "G302"):
		return "Use restrictive file permissions. Avoid world-readable or world-writable files."
	case strings.HasPrefix(ruleID, "G401"):
		return "Use strong cryptographic algorithms (AES-256, SHA-256 or better). Avoid MD5 and SHA1."
	case strings.HasPrefix(ruleID, "G501"), strings.HasPrefix(ruleID, "G502"):
		return "Use TLS 1.2 or higher. Avoid deprecated protocols and cipher suites."
	case strings.Contains(ruleID, "secret"), strings.Contains(ruleID, "credential"):
		return "Remove the secret from source code. Use environment variables or a secret manager."
	default:
		return "Review the finding and apply appropriate security measures based on the context."
	}
}
