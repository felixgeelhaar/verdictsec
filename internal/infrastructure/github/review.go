package github

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// ReviewBuilder builds a PR review from findings.
type ReviewBuilder struct {
	client   *Client
	prNumber int
	prFiles  map[string]bool // Set of files changed in PR
}

// NewReviewBuilder creates a new review builder.
func NewReviewBuilder(client *Client, prNumber int) *ReviewBuilder {
	return &ReviewBuilder{
		client:   client,
		prNumber: prNumber,
		prFiles:  make(map[string]bool),
	}
}

// LoadPRFiles loads the list of files changed in the PR.
func (b *ReviewBuilder) LoadPRFiles(ctx context.Context) error {
	files, err := b.client.GetPRFiles(ctx, b.prNumber)
	if err != nil {
		return fmt.Errorf("failed to get PR files: %w", err)
	}

	for _, f := range files {
		b.prFiles[f.Filename] = true
	}

	return nil
}

// FilterFindings filters findings to only those in files changed by the PR.
func (b *ReviewBuilder) FilterFindings(findings []*finding.Finding) []*finding.Finding {
	var filtered []*finding.Finding
	for _, f := range findings {
		// Normalize path to match GitHub's format
		filePath := normalizePath(f.Location().File())
		if b.prFiles[filePath] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// BuildReview creates a GitHub review from findings.
func (b *ReviewBuilder) BuildReview(findings []*finding.Finding) Review {
	if len(findings) == 0 {
		return Review{
			Body:  "✅ **VerdictSec Security Scan**\n\nNo security findings detected in this PR.",
			Event: "COMMENT",
		}
	}

	comments := make([]ReviewComment, 0, len(findings))
	for _, f := range findings {
		comment := b.buildComment(f)
		comments = append(comments, comment)
	}

	// Build summary body
	summary := b.buildSummaryBody(findings)

	event := "COMMENT"
	if hasCriticalOrHigh(findings) {
		event = "REQUEST_CHANGES"
	}

	return Review{
		Body:     summary,
		Event:    event,
		Comments: comments,
	}
}

// buildComment creates a review comment for a finding.
func (b *ReviewBuilder) buildComment(f *finding.Finding) ReviewComment {
	body := b.formatFindingComment(f)
	filePath := normalizePath(f.Location().File())

	return ReviewComment{
		Path: filePath,
		Line: f.Location().Line(),
		Side: "RIGHT",
		Body: body,
	}
}

// formatFindingComment formats a finding as a markdown comment.
func (b *ReviewBuilder) formatFindingComment(f *finding.Finding) string {
	var sb strings.Builder

	// Severity emoji
	emoji := severityEmoji(f.EffectiveSeverity())

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
	sb.WriteString("\n<details>\n<summary>💡 Remediation</summary>\n\n")
	sb.WriteString(b.getRemediationHint(f))
	sb.WriteString("\n</details>\n")

	return sb.String()
}

// getRemediationHint returns a remediation hint for a finding.
func (b *ReviewBuilder) getRemediationHint(f *finding.Finding) string {
	// Generic hints based on rule patterns
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

// buildSummaryBody creates the review summary body.
func (b *ReviewBuilder) buildSummaryBody(findings []*finding.Finding) string {
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
		sb.WriteString("## 🚨 **VerdictSec Security Scan - Action Required**\n\n")
	} else {
		sb.WriteString("## ⚠️ **VerdictSec Security Scan - Review Recommended**\n\n")
	}

	// Summary table
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	if critical > 0 {
		sb.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", critical))
	}
	if high > 0 {
		sb.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", high))
	}
	if medium > 0 {
		sb.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", medium))
	}
	if low > 0 {
		sb.WriteString(fmt.Sprintf("| 🔵 Low | %d |\n", low))
	}
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n", len(findings)))
	sb.WriteString("\n")

	// Action items
	if critical > 0 {
		sb.WriteString("### ❌ Critical findings must be resolved before merge\n\n")
	} else if high > 0 {
		sb.WriteString("### ⚠️ High severity findings should be addressed\n\n")
	}

	sb.WriteString("Please review the inline comments for detailed findings and remediation guidance.\n")

	return sb.String()
}

// severityEmoji returns an emoji for a severity level.
func severityEmoji(sev finding.Severity) string {
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

// hasCriticalOrHigh returns true if any finding is critical or high severity.
func hasCriticalOrHigh(findings []*finding.Finding) bool {
	for _, f := range findings {
		sev := f.EffectiveSeverity()
		if sev == finding.SeverityCritical || sev == finding.SeverityHigh {
			return true
		}
	}
	return false
}

// normalizePath normalizes a file path to match GitHub's format.
func normalizePath(path string) string {
	// Remove leading ./ if present
	path = strings.TrimPrefix(path, "./")
	// Convert to forward slashes
	path = filepath.ToSlash(path)
	return path
}

// SubmitReview submits a review to the PR.
func (b *ReviewBuilder) SubmitReview(ctx context.Context, review Review) error {
	return b.client.CreateReview(ctx, b.prNumber, review)
}

// PostSummaryComment posts a summary comment without inline annotations.
func (b *ReviewBuilder) PostSummaryComment(ctx context.Context, findings []*finding.Finding) error {
	body := b.buildSummaryBody(findings)
	return b.client.CreateIssueComment(ctx, b.prNumber, body)
}
