package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// GitHubProvider implements PRProvider for GitHub.
type GitHubProvider struct {
	token      string
	owner      string
	repo       string
	prNumber   int
	client     *http.Client
	baseURL    string
	repository string
}

// NewGitHubProvider creates a new GitHub provider.
func NewGitHubProvider(config ProviderConfig) (*GitHubProvider, error) {
	token := config.Token
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		// Try to get token from gh CLI
		var err error
		token, err = getGHToken()
		if err != nil {
			return nil, fmt.Errorf("%w: set GITHUB_TOKEN or authenticate with gh CLI", ErrMissingToken)
		}
	}

	repo := config.Repository
	if repo == "" {
		repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if repo == "" {
		return nil, ErrMissingRepository
	}

	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: invalid repository format %q (expected owner/repo)", ErrInvalidConfiguration, repo)
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	return &GitHubProvider{
		token:      token,
		owner:      parts[0],
		repo:       parts[1],
		prNumber:   config.PRNumber,
		client:     &http.Client{},
		baseURL:    baseURL,
		repository: repo,
	}, nil
}

// getGHToken tries to get a token from the gh CLI.
func getGHToken() (string, error) {
	cmd := exec.Command("gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get token from gh CLI: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// Name returns the provider name.
func (p *GitHubProvider) Name() ProviderName {
	return ProviderGitHub
}

// PRNumber returns the PR number.
func (p *GitHubProvider) PRNumber() int {
	return p.prNumber
}

// Repository returns the repository identifier.
func (p *GitHubProvider) Repository() string {
	return p.repository
}

// PRFile represents a file changed in a PR.
type prFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
}

// GetChangedFiles returns the list of files changed in the PR.
func (p *GitHubProvider) GetChangedFiles(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files", p.baseURL, p.owner, p.repo, p.prNumber)

	var allFiles []string
	page := 1

	for {
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s?page=%d&per_page=100", url, page), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+p.token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := p.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch PR files: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("GitHub API error: %s - %s", resp.Status, string(body))
		}

		var files []prFile
		if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		for _, f := range files {
			allFiles = append(allFiles, f.Filename)
		}

		if len(files) < 100 {
			break
		}
		page++
	}

	return allFiles, nil
}

// gitHubReview represents a GitHub PR review.
type gitHubReview struct {
	Body     string                `json:"body"`
	Event    string                `json:"event"`
	Comments []gitHubReviewComment `json:"comments,omitempty"`
}

// gitHubReviewComment represents a comment in a GitHub review.
type gitHubReviewComment struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	Side string `json:"side,omitempty"`
	Body string `json:"body"`
}

// CreateReview creates a review on the PR with inline comments.
func (p *GitHubProvider) CreateReview(ctx context.Context, comments []ReviewComment, summary string, requestChanges bool) error {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/reviews", p.baseURL, p.owner, p.repo, p.prNumber)

	// Convert to GitHub format
	ghComments := make([]gitHubReviewComment, 0, len(comments))
	for _, c := range comments {
		ghComments = append(ghComments, gitHubReviewComment{
			Path: c.Path,
			Line: c.Line,
			Side: c.Side,
			Body: c.Body,
		})
	}

	event := "COMMENT"
	if requestChanges {
		event = "REQUEST_CHANGES"
	}

	review := gitHubReview{
		Body:     summary,
		Event:    event,
		Comments: ghComments,
	}

	body, err := json.Marshal(review)
	if err != nil {
		return fmt.Errorf("failed to marshal review: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create review: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error: %s - %s", resp.Status, string(respBody))
	}

	return nil
}

// PostSummary posts a standalone comment on the PR.
func (p *GitHubProvider) PostSummary(ctx context.Context, summary string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", p.baseURL, p.owner, p.repo, p.prNumber)

	comment := map[string]string{"body": summary}
	commentJSON, err := json.Marshal(comment)
	if err != nil {
		return fmt.Errorf("failed to marshal comment: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(commentJSON)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create comment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error: %s - %s", resp.Status, string(respBody))
	}

	return nil
}
