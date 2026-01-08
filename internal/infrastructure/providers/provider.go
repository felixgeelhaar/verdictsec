// Package providers defines the abstraction for PR/MR annotation providers.
package providers

import (
	"context"
	"errors"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// ProviderName represents a supported provider.
type ProviderName string

const (
	ProviderGitHub    ProviderName = "github"
	ProviderGitLab    ProviderName = "gitlab"
	ProviderBitbucket ProviderName = "bitbucket"
)

// Common errors.
var (
	ErrNoProviderDetected   = errors.New("no CI provider detected from environment")
	ErrMissingToken         = errors.New("authentication token not configured")
	ErrMissingRepository    = errors.New("repository not configured")
	ErrMissingPRNumber      = errors.New("PR/MR number not configured")
	ErrUnsupportedProvider  = errors.New("unsupported provider")
	ErrInvalidConfiguration = errors.New("invalid provider configuration")
)

// ReviewComment represents a comment to post on a PR/MR.
type ReviewComment struct {
	// Path is the file path relative to the repository root.
	Path string

	// Line is the line number in the file (1-based).
	Line int

	// Side indicates which side of the diff (RIGHT for new code, LEFT for removed).
	Side string

	// Body is the markdown content of the comment.
	Body string

	// Severity is the finding severity for categorization.
	Severity finding.Severity
}

// PRProvider is the interface for interacting with PR/MR systems.
type PRProvider interface {
	// Name returns the provider name (github, gitlab, bitbucket).
	Name() ProviderName

	// GetChangedFiles returns the list of files modified in the PR/MR.
	GetChangedFiles(ctx context.Context) ([]string, error)

	// CreateReview posts security findings as review comments.
	// For GitHub, this creates a review with inline comments.
	// For GitLab, this creates discussion threads.
	// For Bitbucket, this creates inline comments on the diff.
	CreateReview(ctx context.Context, comments []ReviewComment, summary string, requestChanges bool) error

	// PostSummary posts a standalone summary comment on the PR/MR.
	PostSummary(ctx context.Context, summary string) error

	// PRNumber returns the PR/MR number being annotated.
	PRNumber() int

	// Repository returns the repository identifier (owner/repo format).
	Repository() string
}

// ProviderConfig contains common configuration for all providers.
type ProviderConfig struct {
	// Token is the authentication token (API key, personal access token, etc.).
	Token string

	// Repository is the repository identifier (format varies by provider).
	Repository string

	// PRNumber is the PR/MR number to annotate.
	PRNumber int

	// BaseURL allows overriding the API endpoint for self-hosted instances.
	BaseURL string
}

// Validate checks that required configuration is present.
func (c *ProviderConfig) Validate() error {
	if c.Token == "" {
		return ErrMissingToken
	}
	if c.Repository == "" {
		return ErrMissingRepository
	}
	if c.PRNumber <= 0 {
		return ErrMissingPRNumber
	}
	return nil
}
