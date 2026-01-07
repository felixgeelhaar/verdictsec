package writers

import (
	"context"
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/github"
)

// GitHubPRWriter posts findings as PR review comments.
type GitHubPRWriter struct {
	client   *github.Client
	prNumber int
	builder  *github.ReviewBuilder
	ctx      context.Context

	// Fallback console writer for progress
	console *ConsoleWriter
}

// GitHubPRWriterConfig configures the GitHub PR writer.
type GitHubPRWriterConfig struct {
	Token      string
	Repository string
	PRNumber   int
}

// NewGitHubPRWriter creates a new GitHub PR writer.
func NewGitHubPRWriter(ctx context.Context, cfg GitHubPRWriterConfig) (*GitHubPRWriter, error) {
	client, err := github.NewClient(github.ClientConfig{
		Token:      cfg.Token,
		Repository: cfg.Repository,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub client: %w", err)
	}

	builder := github.NewReviewBuilder(client, cfg.PRNumber)

	// Load PR files for filtering
	if err := builder.LoadPRFiles(ctx); err != nil {
		return nil, fmt.Errorf("failed to load PR files: %w", err)
	}

	return &GitHubPRWriter{
		client:   client,
		prNumber: cfg.PRNumber,
		builder:  builder,
		ctx:      ctx,
		console:  NewConsoleWriter(),
	}, nil
}

// WriteAssessment posts findings as a PR review.
func (w *GitHubPRWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	// Filter findings to only those in PR files
	allFindings := a.Findings()
	prFindings := w.builder.FilterFindings(allFindings)

	// Build and submit review
	review := w.builder.BuildReview(prFindings)

	if err := w.builder.SubmitReview(w.ctx, review); err != nil {
		return fmt.Errorf("failed to submit PR review: %w", err)
	}

	// Log to console
	w.console.WriteProgress(fmt.Sprintf("Posted %d findings to PR #%d (%d total findings, %d in PR files)",
		len(prFindings), w.prNumber, len(allFindings), len(prFindings)))

	return nil
}

// WriteSummary posts a summary comment to the PR.
func (w *GitHubPRWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	// Filter findings to only those in PR files
	prFindings := w.builder.FilterFindings(a.Findings())

	if err := w.builder.PostSummaryComment(w.ctx, prFindings); err != nil {
		return fmt.Errorf("failed to post summary comment: %w", err)
	}

	return nil
}

// WriteProgress writes a progress message to console (not to PR).
func (w *GitHubPRWriter) WriteProgress(message string) error {
	return w.console.WriteProgress(message)
}

// WriteError writes an error message to console.
func (w *GitHubPRWriter) WriteError(err error) error {
	return w.console.WriteError(err)
}

// Flush ensures all output is written.
func (w *GitHubPRWriter) Flush() error {
	return nil
}
