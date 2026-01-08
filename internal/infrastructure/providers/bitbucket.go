package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

// BitbucketProvider implements PRProvider for Bitbucket.
type BitbucketProvider struct {
	token      string
	workspace  string
	repoSlug   string
	prID       int
	client     *http.Client
	baseURL    string
	repository string
}

// NewBitbucketProvider creates a new Bitbucket provider.
func NewBitbucketProvider(config ProviderConfig) (*BitbucketProvider, error) {
	token := config.Token
	if token == "" {
		token = os.Getenv("BITBUCKET_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("%w: set BITBUCKET_TOKEN", ErrMissingToken)
	}

	repo := config.Repository
	if repo == "" {
		workspace := os.Getenv("BITBUCKET_WORKSPACE")
		repoSlug := os.Getenv("BITBUCKET_REPO_SLUG")
		if workspace != "" && repoSlug != "" {
			repo = workspace + "/" + repoSlug
		}
	}
	if repo == "" {
		return nil, ErrMissingRepository
	}

	// Parse workspace/repo_slug
	var workspace, repoSlug string
	for i := 0; i < len(repo); i++ {
		if repo[i] == '/' {
			workspace = repo[:i]
			repoSlug = repo[i+1:]
			break
		}
	}
	if workspace == "" || repoSlug == "" {
		return nil, fmt.Errorf("%w: invalid repository format %q (expected workspace/repo_slug)", ErrInvalidConfiguration, repo)
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = os.Getenv("BITBUCKET_API_URL")
	}
	if baseURL == "" {
		baseURL = "https://api.bitbucket.org/2.0"
	}

	prID := config.PRNumber
	if prID == 0 {
		if prStr := os.Getenv("BITBUCKET_PR_ID"); prStr != "" {
			n, err := strconv.Atoi(prStr)
			if err != nil {
				return nil, fmt.Errorf("invalid BITBUCKET_PR_ID: %w", err)
			}
			prID = n
		}
	}

	return &BitbucketProvider{
		token:      token,
		workspace:  workspace,
		repoSlug:   repoSlug,
		prID:       prID,
		client:     &http.Client{},
		baseURL:    baseURL,
		repository: repo,
	}, nil
}

// Name returns the provider name.
func (p *BitbucketProvider) Name() ProviderName {
	return ProviderBitbucket
}

// PRNumber returns the PR ID.
func (p *BitbucketProvider) PRNumber() int {
	return p.prID
}

// Repository returns the repository identifier.
func (p *BitbucketProvider) Repository() string {
	return p.repository
}

// bitbucketDiffstat represents a file in the PR diffstat.
type bitbucketDiffstat struct {
	Status  string `json:"status"`
	NewPath struct {
		Path string `json:"path"`
	} `json:"new"`
	OldPath struct {
		Path string `json:"path"`
	} `json:"old"`
}

// bitbucketDiffstatResponse represents the diffstat API response.
type bitbucketDiffstatResponse struct {
	Values []bitbucketDiffstat `json:"values"`
	Next   string              `json:"next,omitempty"`
}

// GetChangedFiles returns the list of files changed in the PR.
func (p *BitbucketProvider) GetChangedFiles(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/repositories/%s/%s/pullrequests/%d/diffstat", p.baseURL, p.workspace, p.repoSlug, p.prID)

	var allFiles []string

	for url != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		p.setAuthHeader(req)

		resp, err := p.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch PR diffstat: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("bitbucket API error: %s - %s", resp.Status, string(body))
		}

		var diffstat bitbucketDiffstatResponse
		if err := json.NewDecoder(resp.Body).Decode(&diffstat); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		for _, d := range diffstat.Values {
			// Use new path for added/modified files
			if d.NewPath.Path != "" {
				allFiles = append(allFiles, d.NewPath.Path)
			} else if d.OldPath.Path != "" && d.Status != "removed" {
				allFiles = append(allFiles, d.OldPath.Path)
			}
		}

		url = diffstat.Next
	}

	return allFiles, nil
}

// bitbucketComment represents a comment on a Bitbucket PR.
type bitbucketComment struct {
	Content struct {
		Raw string `json:"raw"`
	} `json:"content"`
	Inline *bitbucketInline `json:"inline,omitempty"`
}

// bitbucketInline represents inline position for a comment.
type bitbucketInline struct {
	Path string `json:"path"`
	To   int    `json:"to,omitempty"` // Line in the new version
	From int    `json:"from,omitempty"`
}

// CreateReview creates inline comments on the PR.
// Bitbucket doesn't have a review concept, so we create individual comments.
func (p *BitbucketProvider) CreateReview(ctx context.Context, comments []ReviewComment, summary string, requestChanges bool) error {
	// Create individual inline comments for each finding
	for _, comment := range comments {
		bbComment := bitbucketComment{
			Content: struct {
				Raw string `json:"raw"`
			}{
				Raw: comment.Body,
			},
			Inline: &bitbucketInline{
				Path: comment.Path,
				To:   comment.Line,
			},
		}

		if err := p.createComment(ctx, bbComment); err != nil {
			// If inline comment fails, try posting as a regular comment
			bbComment.Inline = nil
			bbComment.Content.Raw = fmt.Sprintf("**%s:%d**\n\n%s", comment.Path, comment.Line, comment.Body)
			if err := p.createComment(ctx, bbComment); err != nil {
				return fmt.Errorf("failed to create comment: %w", err)
			}
		}
	}

	// Post the summary as a regular comment
	if summary != "" {
		return p.PostSummary(ctx, summary)
	}

	return nil
}

// createComment creates a comment on the PR.
func (p *BitbucketProvider) createComment(ctx context.Context, comment bitbucketComment) error {
	url := fmt.Sprintf("%s/repositories/%s/%s/pullrequests/%d/comments", p.baseURL, p.workspace, p.repoSlug, p.prID)

	body, err := json.Marshal(comment)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	p.setAuthHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bitbucket API error: %s - %s", resp.Status, string(respBody))
	}

	return nil
}

// PostSummary posts a standalone comment on the PR.
func (p *BitbucketProvider) PostSummary(ctx context.Context, summary string) error {
	comment := bitbucketComment{
		Content: struct {
			Raw string `json:"raw"`
		}{
			Raw: summary,
		},
	}
	return p.createComment(ctx, comment)
}

// setAuthHeader sets the appropriate auth header for Bitbucket.
func (p *BitbucketProvider) setAuthHeader(req *http.Request) {
	// Bitbucket Cloud uses Bearer token (app password or OAuth)
	req.Header.Set("Authorization", "Bearer "+p.token)
}
