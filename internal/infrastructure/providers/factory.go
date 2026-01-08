package providers

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Factory creates PR providers based on configuration or environment detection.
type Factory struct{}

// NewFactory creates a new provider factory.
func NewFactory() *Factory {
	return &Factory{}
}

// DetectProvider attempts to auto-detect the CI environment and create the appropriate provider.
func (f *Factory) DetectProvider() (PRProvider, error) {
	// Check GitHub Actions
	if IsGitHubActions() {
		config, err := GitHubConfigFromEnv()
		if err != nil {
			return nil, fmt.Errorf("detected GitHub Actions but: %w", err)
		}
		return NewGitHubProvider(config)
	}

	// Check GitLab CI
	if IsGitLabCI() {
		config, err := GitLabConfigFromEnv()
		if err != nil {
			return nil, fmt.Errorf("detected GitLab CI but: %w", err)
		}
		return NewGitLabProvider(config)
	}

	// Check Bitbucket Pipelines
	if IsBitbucketPipelines() {
		config, err := BitbucketConfigFromEnv()
		if err != nil {
			return nil, fmt.Errorf("detected Bitbucket Pipelines but: %w", err)
		}
		return NewBitbucketProvider(config)
	}

	return nil, ErrNoProviderDetected
}

// CreateProvider creates a specific provider with the given configuration.
func (f *Factory) CreateProvider(name ProviderName, config ProviderConfig) (PRProvider, error) {
	switch name {
	case ProviderGitHub:
		return NewGitHubProvider(config)
	case ProviderGitLab:
		return NewGitLabProvider(config)
	case ProviderBitbucket:
		return NewBitbucketProvider(config)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProvider, name)
	}
}

// Detection functions for each CI platform.

// IsGitHubActions returns true if running in GitHub Actions.
func IsGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}

// IsGitLabCI returns true if running in GitLab CI.
func IsGitLabCI() bool {
	return os.Getenv("GITLAB_CI") == "true"
}

// IsBitbucketPipelines returns true if running in Bitbucket Pipelines.
func IsBitbucketPipelines() bool {
	return os.Getenv("BITBUCKET_BUILD_NUMBER") != ""
}

// Configuration extraction from environment.

// GitHubConfigFromEnv creates GitHub configuration from environment variables.
func GitHubConfigFromEnv() (ProviderConfig, error) {
	config := ProviderConfig{
		Token:      os.Getenv("GITHUB_TOKEN"),
		Repository: os.Getenv("GITHUB_REPOSITORY"),
		BaseURL:    os.Getenv("GITHUB_API_URL"),
	}

	// Default API URL
	if config.BaseURL == "" {
		config.BaseURL = "https://api.github.com"
	}

	// Parse PR number from GITHUB_REF (refs/pull/123/merge) or explicit var
	if prNum := os.Getenv("GITHUB_PR_NUMBER"); prNum != "" {
		n, err := strconv.Atoi(prNum)
		if err != nil {
			return config, fmt.Errorf("invalid GITHUB_PR_NUMBER: %w", err)
		}
		config.PRNumber = n
	} else if ref := os.Getenv("GITHUB_REF"); strings.HasPrefix(ref, "refs/pull/") {
		// Extract from refs/pull/123/merge
		parts := strings.Split(ref, "/")
		if len(parts) >= 3 {
			n, err := strconv.Atoi(parts[2])
			if err == nil {
				config.PRNumber = n
			}
		}
	}

	return config, nil
}

// GitLabConfigFromEnv creates GitLab configuration from environment variables.
func GitLabConfigFromEnv() (ProviderConfig, error) {
	// GitLab supports multiple token types
	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		token = os.Getenv("CI_JOB_TOKEN")
	}

	// Get project path (group/project)
	repo := os.Getenv("CI_PROJECT_PATH")
	if repo == "" {
		// Try constructing from namespace and project name
		namespace := os.Getenv("CI_PROJECT_NAMESPACE")
		name := os.Getenv("CI_PROJECT_NAME")
		if namespace != "" && name != "" {
			repo = namespace + "/" + name
		}
	}

	config := ProviderConfig{
		Token:      token,
		Repository: repo,
		BaseURL:    os.Getenv("CI_API_V4_URL"),
	}

	// Default API URL
	if config.BaseURL == "" {
		config.BaseURL = "https://gitlab.com/api/v4"
	}

	// Parse MR IID (internal ID within project)
	if mrIID := os.Getenv("CI_MERGE_REQUEST_IID"); mrIID != "" {
		n, err := strconv.Atoi(mrIID)
		if err != nil {
			return config, fmt.Errorf("invalid CI_MERGE_REQUEST_IID: %w", err)
		}
		config.PRNumber = n
	}

	return config, nil
}

// BitbucketConfigFromEnv creates Bitbucket configuration from environment variables.
func BitbucketConfigFromEnv() (ProviderConfig, error) {
	// Bitbucket uses workspace/repo_slug format
	workspace := os.Getenv("BITBUCKET_WORKSPACE")
	repoSlug := os.Getenv("BITBUCKET_REPO_SLUG")

	repo := ""
	if workspace != "" && repoSlug != "" {
		repo = workspace + "/" + repoSlug
	}

	config := ProviderConfig{
		Token:      os.Getenv("BITBUCKET_TOKEN"),
		Repository: repo,
		BaseURL:    os.Getenv("BITBUCKET_API_URL"),
	}

	// Default API URL
	if config.BaseURL == "" {
		config.BaseURL = "https://api.bitbucket.org/2.0"
	}

	// Parse PR ID
	if prID := os.Getenv("BITBUCKET_PR_ID"); prID != "" {
		n, err := strconv.Atoi(prID)
		if err != nil {
			return config, fmt.Errorf("invalid BITBUCKET_PR_ID: %w", err)
		}
		config.PRNumber = n
	}

	return config, nil
}

// ParseProviderName converts a string to ProviderName.
func ParseProviderName(s string) (ProviderName, error) {
	switch strings.ToLower(s) {
	case "github", "gh":
		return ProviderGitHub, nil
	case "gitlab", "gl":
		return ProviderGitLab, nil
	case "bitbucket", "bb":
		return ProviderBitbucket, nil
	case "auto", "":
		return "", nil // Will trigger auto-detection
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedProvider, s)
	}
}
