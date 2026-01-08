package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

// GitLabProvider implements PRProvider for GitLab.
type GitLabProvider struct {
	token      string
	projectID  string // URL-encoded project path (group%2Fproject)
	mrIID      int    // Merge request internal ID
	client     *http.Client
	baseURL    string
	repository string
}

// NewGitLabProvider creates a new GitLab provider.
func NewGitLabProvider(config ProviderConfig) (*GitLabProvider, error) {
	token := config.Token
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("CI_JOB_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("%w: set GITLAB_TOKEN or CI_JOB_TOKEN", ErrMissingToken)
	}

	repo := config.Repository
	if repo == "" {
		repo = os.Getenv("CI_PROJECT_PATH")
	}
	if repo == "" {
		return nil, ErrMissingRepository
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = os.Getenv("CI_API_V4_URL")
	}
	if baseURL == "" {
		baseURL = "https://gitlab.com/api/v4"
	}

	mrIID := config.PRNumber
	if mrIID == 0 {
		if mrStr := os.Getenv("CI_MERGE_REQUEST_IID"); mrStr != "" {
			n, err := strconv.Atoi(mrStr)
			if err != nil {
				return nil, fmt.Errorf("invalid CI_MERGE_REQUEST_IID: %w", err)
			}
			mrIID = n
		}
	}

	return &GitLabProvider{
		token:      token,
		projectID:  url.PathEscape(repo),
		mrIID:      mrIID,
		client:     &http.Client{},
		baseURL:    baseURL,
		repository: repo,
	}, nil
}

// Name returns the provider name.
func (p *GitLabProvider) Name() ProviderName {
	return ProviderGitLab
}

// PRNumber returns the MR IID.
func (p *GitLabProvider) PRNumber() int {
	return p.mrIID
}

// Repository returns the repository identifier.
func (p *GitLabProvider) Repository() string {
	return p.repository
}

// gitLabDiff represents a changed file in a GitLab MR.
type gitLabDiff struct {
	OldPath     string `json:"old_path"`
	NewPath     string `json:"new_path"`
	AMode       string `json:"a_mode"`
	BMode       string `json:"b_mode"`
	Diff        string `json:"diff"`
	NewFile     bool   `json:"new_file"`
	RenamedFile bool   `json:"renamed_file"`
	DeletedFile bool   `json:"deleted_file"`
}

// gitLabMRChanges represents the MR changes response.
type gitLabMRChanges struct {
	Changes []gitLabDiff `json:"changes"`
}

// GetChangedFiles returns the list of files changed in the MR.
func (p *GitLabProvider) GetChangedFiles(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/projects/%s/merge_requests/%d/changes", p.baseURL, p.projectID, p.mrIID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	p.setAuthHeader(req)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch MR changes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitLab API error: %s - %s", resp.Status, string(body))
	}

	var changes gitLabMRChanges
	if err := json.NewDecoder(resp.Body).Decode(&changes); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	files := make([]string, 0, len(changes.Changes))
	for _, c := range changes.Changes {
		if !c.DeletedFile {
			files = append(files, c.NewPath)
		}
	}

	return files, nil
}

// gitLabDiscussionNote represents a note in a discussion.
type gitLabDiscussionNote struct {
	Body string `json:"body"`
}

// gitLabDiscussionPosition represents the position of a discussion.
type gitLabDiscussionPosition struct {
	BaseSHA      string `json:"base_sha,omitempty"`
	StartSHA     string `json:"start_sha,omitempty"`
	HeadSHA      string `json:"head_sha,omitempty"`
	PositionType string `json:"position_type"`
	NewPath      string `json:"new_path,omitempty"`
	NewLine      int    `json:"new_line,omitempty"`
	OldPath      string `json:"old_path,omitempty"`
	OldLine      int    `json:"old_line,omitempty"`
}

// gitLabDiscussion represents a discussion on a GitLab MR.
type gitLabDiscussion struct {
	Body     string                    `json:"body"`
	Position *gitLabDiscussionPosition `json:"position,omitempty"`
}

// CreateReview creates inline discussions on the MR.
// GitLab doesn't have a review concept like GitHub, so we create individual discussions.
func (p *GitLabProvider) CreateReview(ctx context.Context, comments []ReviewComment, summary string, requestChanges bool) error {
	// First, get the MR details to get the SHAs for positioning
	mrInfo, err := p.getMRInfo(ctx)
	if err != nil {
		// If we can't get MR info, fall back to posting a summary comment
		return p.PostSummary(ctx, summary)
	}

	// Create individual discussions for each comment
	for _, comment := range comments {
		discussion := gitLabDiscussion{
			Body: comment.Body,
			Position: &gitLabDiscussionPosition{
				BaseSHA:      mrInfo.DiffRefs.BaseSHA,
				StartSHA:     mrInfo.DiffRefs.StartSHA,
				HeadSHA:      mrInfo.DiffRefs.HeadSHA,
				PositionType: "text",
				NewPath:      comment.Path,
				NewLine:      comment.Line,
			},
		}

		if err := p.createDiscussion(ctx, discussion); err != nil {
			// If creating inline discussion fails, try posting as a regular note
			if err := p.createNote(ctx, comment.Body); err != nil {
				return fmt.Errorf("failed to create discussion: %w", err)
			}
		}
	}

	// Post the summary as a note
	if summary != "" {
		if err := p.createNote(ctx, summary); err != nil {
			return fmt.Errorf("failed to post summary: %w", err)
		}
	}

	return nil
}

// gitLabMRInfo represents MR metadata.
type gitLabMRInfo struct {
	DiffRefs struct {
		BaseSHA  string `json:"base_sha"`
		HeadSHA  string `json:"head_sha"`
		StartSHA string `json:"start_sha"`
	} `json:"diff_refs"`
}

// getMRInfo fetches MR metadata including diff refs.
func (p *GitLabProvider) getMRInfo(ctx context.Context) (*gitLabMRInfo, error) {
	url := fmt.Sprintf("%s/projects/%s/merge_requests/%d", p.baseURL, p.projectID, p.mrIID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	p.setAuthHeader(req)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitLab API error: %s - %s", resp.Status, string(body))
	}

	var info gitLabMRInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

// createDiscussion creates a discussion on the MR.
func (p *GitLabProvider) createDiscussion(ctx context.Context, discussion gitLabDiscussion) error {
	url := fmt.Sprintf("%s/projects/%s/merge_requests/%d/discussions", p.baseURL, p.projectID, p.mrIID)

	body, err := json.Marshal(discussion)
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
		return fmt.Errorf("GitLab API error: %s - %s", resp.Status, string(respBody))
	}

	return nil
}

// createNote creates a simple note (comment) on the MR.
func (p *GitLabProvider) createNote(ctx context.Context, body string) error {
	url := fmt.Sprintf("%s/projects/%s/merge_requests/%d/notes", p.baseURL, p.projectID, p.mrIID)

	note := map[string]string{"body": body}
	noteJSON, err := json.Marshal(note)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(noteJSON))
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
		return fmt.Errorf("GitLab API error: %s - %s", resp.Status, string(respBody))
	}

	return nil
}

// PostSummary posts a standalone note on the MR.
func (p *GitLabProvider) PostSummary(ctx context.Context, summary string) error {
	return p.createNote(ctx, summary)
}

// setAuthHeader sets the appropriate auth header for GitLab.
func (p *GitLabProvider) setAuthHeader(req *http.Request) {
	// GitLab accepts both PRIVATE-TOKEN and Bearer token
	req.Header.Set("PRIVATE-TOKEN", p.token)
}
