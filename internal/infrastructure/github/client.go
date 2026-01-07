// Package github provides GitHub API integration for PR annotations.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Client provides GitHub API access.
type Client struct {
	token    string
	owner    string
	repo     string
	client   *http.Client
	baseURL  string
}

// ClientConfig contains configuration for the GitHub client.
type ClientConfig struct {
	Token      string // GITHUB_TOKEN
	Repository string // owner/repo format
	BaseURL    string // API base URL (defaults to api.github.com)
}

// NewClient creates a new GitHub client.
func NewClient(cfg ClientConfig) (*Client, error) {
	token := cfg.Token
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	if token == "" {
		// Try to get token from gh CLI
		var err error
		token, err = getGHToken()
		if err != nil {
			return nil, fmt.Errorf("no GitHub token available (set GITHUB_TOKEN or authenticate with gh CLI)")
		}
	}

	repo := cfg.Repository
	if repo == "" {
		repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if repo == "" {
		return nil, fmt.Errorf("repository not specified (set GITHUB_REPOSITORY or use --repo)")
	}

	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository format: %q (expected owner/repo)", repo)
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	return &Client{
		token:   token,
		owner:   parts[0],
		repo:    parts[1],
		client:  &http.Client{},
		baseURL: baseURL,
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

// Owner returns the repository owner.
func (c *Client) Owner() string {
	return c.owner
}

// Repo returns the repository name.
func (c *Client) Repo() string {
	return c.repo
}

// PRFile represents a file changed in a PR.
type PRFile struct {
	Filename    string `json:"filename"`
	Status      string `json:"status"`
	Additions   int    `json:"additions"`
	Deletions   int    `json:"deletions"`
	Changes     int    `json:"changes"`
	Patch       string `json:"patch,omitempty"`
	BlobURL     string `json:"blob_url"`
	RawURL      string `json:"raw_url"`
	ContentsURL string `json:"contents_url"`
}

// GetPRFiles returns the list of files changed in a PR.
func (c *Client) GetPRFiles(ctx context.Context, prNumber int) ([]PRFile, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files", c.baseURL, c.owner, c.repo, prNumber)

	var allFiles []PRFile
	page := 1

	for {
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s?page=%d&per_page=100", url, page), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch PR files: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("GitHub API error: %s - %s", resp.Status, string(body))
		}

		var files []PRFile
		if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		allFiles = append(allFiles, files...)

		// Check if there are more pages
		if len(files) < 100 {
			break
		}
		page++
	}

	return allFiles, nil
}

// ReviewComment represents a comment on a PR review.
type ReviewComment struct {
	Path     string `json:"path"`
	Line     int    `json:"line,omitempty"`
	Side     string `json:"side,omitempty"` // LEFT or RIGHT
	Body     string `json:"body"`
	Position int    `json:"position,omitempty"` // Deprecated, use line
}

// Review represents a PR review.
type Review struct {
	Body     string          `json:"body"`
	Event    string          `json:"event"` // APPROVE, REQUEST_CHANGES, COMMENT
	Comments []ReviewComment `json:"comments,omitempty"`
}

// CreateReview creates a review on a PR with inline comments.
func (c *Client) CreateReview(ctx context.Context, prNumber int, review Review) error {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/reviews", c.baseURL, c.owner, c.repo, prNumber)

	body, err := json.Marshal(review)
	if err != nil {
		return fmt.Errorf("failed to marshal review: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
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

// CreateIssueComment creates a comment on a PR (not a review comment).
func (c *Client) CreateIssueComment(ctx context.Context, prNumber int, body string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", c.baseURL, c.owner, c.repo, prNumber)

	comment := map[string]string{"body": body}
	commentJSON, err := json.Marshal(comment)
	if err != nil {
		return fmt.Errorf("failed to marshal comment: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(commentJSON)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
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

// GetPRNumber returns the PR number from environment or parses it from string.
func GetPRNumber() (int, error) {
	// Check GitHub Actions environment
	if prRef := os.Getenv("GITHUB_REF"); strings.HasPrefix(prRef, "refs/pull/") {
		parts := strings.Split(prRef, "/")
		if len(parts) >= 3 {
			return strconv.Atoi(parts[2])
		}
	}

	// Check explicit env var
	if prNum := os.Getenv("GITHUB_PR_NUMBER"); prNum != "" {
		return strconv.Atoi(prNum)
	}

	return 0, fmt.Errorf("PR number not found (set GITHUB_PR_NUMBER or run in GitHub Actions PR context)")
}

// IsGitHubActions returns true if running in GitHub Actions.
func IsGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}

// GetRepository returns the repository from environment.
func GetRepository() string {
	return os.Getenv("GITHUB_REPOSITORY")
}
