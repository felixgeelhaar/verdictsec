package providers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProviderName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ProviderName
		wantErr  bool
	}{
		{"github", "github", ProviderGitHub, false},
		{"github_short", "gh", ProviderGitHub, false},
		{"gitlab", "gitlab", ProviderGitLab, false},
		{"gitlab_short", "gl", ProviderGitLab, false},
		{"bitbucket", "bitbucket", ProviderBitbucket, false},
		{"bitbucket_short", "bb", ProviderBitbucket, false},
		{"auto", "auto", "", false},
		{"empty", "", "", false},
		{"case_insensitive", "GitHub", ProviderGitHub, false},
		{"unknown", "unknown", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseProviderName(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestIsGitHubActions(t *testing.T) {
	// Save and restore env
	original := os.Getenv("GITHUB_ACTIONS")
	defer os.Setenv("GITHUB_ACTIONS", original)

	os.Setenv("GITHUB_ACTIONS", "true")
	assert.True(t, IsGitHubActions())

	os.Setenv("GITHUB_ACTIONS", "false")
	assert.False(t, IsGitHubActions())

	os.Unsetenv("GITHUB_ACTIONS")
	assert.False(t, IsGitHubActions())
}

func TestIsGitLabCI(t *testing.T) {
	original := os.Getenv("GITLAB_CI")
	defer os.Setenv("GITLAB_CI", original)

	os.Setenv("GITLAB_CI", "true")
	assert.True(t, IsGitLabCI())

	os.Unsetenv("GITLAB_CI")
	assert.False(t, IsGitLabCI())
}

func TestIsBitbucketPipelines(t *testing.T) {
	original := os.Getenv("BITBUCKET_BUILD_NUMBER")
	defer os.Setenv("BITBUCKET_BUILD_NUMBER", original)

	os.Setenv("BITBUCKET_BUILD_NUMBER", "123")
	assert.True(t, IsBitbucketPipelines())

	os.Unsetenv("BITBUCKET_BUILD_NUMBER")
	assert.False(t, IsBitbucketPipelines())
}

func TestGitHubConfigFromEnv(t *testing.T) {
	// Save original values
	origToken := os.Getenv("GITHUB_TOKEN")
	origRepo := os.Getenv("GITHUB_REPOSITORY")
	origAPI := os.Getenv("GITHUB_API_URL")
	origPR := os.Getenv("GITHUB_PR_NUMBER")
	origRef := os.Getenv("GITHUB_REF")

	defer func() {
		os.Setenv("GITHUB_TOKEN", origToken)
		os.Setenv("GITHUB_REPOSITORY", origRepo)
		os.Setenv("GITHUB_API_URL", origAPI)
		os.Setenv("GITHUB_PR_NUMBER", origPR)
		os.Setenv("GITHUB_REF", origRef)
	}()

	t.Run("full config", func(t *testing.T) {
		os.Setenv("GITHUB_TOKEN", "test-token")
		os.Setenv("GITHUB_REPOSITORY", "owner/repo")
		os.Setenv("GITHUB_PR_NUMBER", "42")
		os.Unsetenv("GITHUB_API_URL")
		os.Unsetenv("GITHUB_REF")

		config, err := GitHubConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, "test-token", config.Token)
		assert.Equal(t, "owner/repo", config.Repository)
		assert.Equal(t, 42, config.PRNumber)
		assert.Equal(t, "https://api.github.com", config.BaseURL)
	})

	t.Run("pr from ref", func(t *testing.T) {
		os.Setenv("GITHUB_TOKEN", "test-token")
		os.Setenv("GITHUB_REPOSITORY", "owner/repo")
		os.Unsetenv("GITHUB_PR_NUMBER")
		os.Setenv("GITHUB_REF", "refs/pull/123/merge")

		config, err := GitHubConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, 123, config.PRNumber)
	})

	t.Run("custom api url", func(t *testing.T) {
		os.Setenv("GITHUB_API_URL", "https://github.example.com/api/v3")

		config, err := GitHubConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, "https://github.example.com/api/v3", config.BaseURL)
	})
}

func TestGitLabConfigFromEnv(t *testing.T) {
	// Save original values
	origToken := os.Getenv("GITLAB_TOKEN")
	origJob := os.Getenv("CI_JOB_TOKEN")
	origPath := os.Getenv("CI_PROJECT_PATH")
	origAPI := os.Getenv("CI_API_V4_URL")
	origMR := os.Getenv("CI_MERGE_REQUEST_IID")

	defer func() {
		os.Setenv("GITLAB_TOKEN", origToken)
		os.Setenv("CI_JOB_TOKEN", origJob)
		os.Setenv("CI_PROJECT_PATH", origPath)
		os.Setenv("CI_API_V4_URL", origAPI)
		os.Setenv("CI_MERGE_REQUEST_IID", origMR)
	}()

	t.Run("full config", func(t *testing.T) {
		os.Setenv("GITLAB_TOKEN", "test-token")
		os.Setenv("CI_PROJECT_PATH", "group/project")
		os.Setenv("CI_MERGE_REQUEST_IID", "99")
		os.Unsetenv("CI_JOB_TOKEN")
		os.Unsetenv("CI_API_V4_URL")

		config, err := GitLabConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, "test-token", config.Token)
		assert.Equal(t, "group/project", config.Repository)
		assert.Equal(t, 99, config.PRNumber)
		assert.Equal(t, "https://gitlab.com/api/v4", config.BaseURL)
	})

	t.Run("ci job token fallback", func(t *testing.T) {
		os.Unsetenv("GITLAB_TOKEN")
		os.Setenv("CI_JOB_TOKEN", "job-token")
		os.Setenv("CI_PROJECT_PATH", "group/project")

		config, err := GitLabConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, "job-token", config.Token)
	})
}

func TestBitbucketConfigFromEnv(t *testing.T) {
	// Save original values
	origToken := os.Getenv("BITBUCKET_TOKEN")
	origWS := os.Getenv("BITBUCKET_WORKSPACE")
	origSlug := os.Getenv("BITBUCKET_REPO_SLUG")
	origAPI := os.Getenv("BITBUCKET_API_URL")
	origPR := os.Getenv("BITBUCKET_PR_ID")

	defer func() {
		os.Setenv("BITBUCKET_TOKEN", origToken)
		os.Setenv("BITBUCKET_WORKSPACE", origWS)
		os.Setenv("BITBUCKET_REPO_SLUG", origSlug)
		os.Setenv("BITBUCKET_API_URL", origAPI)
		os.Setenv("BITBUCKET_PR_ID", origPR)
	}()

	t.Run("full config", func(t *testing.T) {
		os.Setenv("BITBUCKET_TOKEN", "test-token")
		os.Setenv("BITBUCKET_WORKSPACE", "myworkspace")
		os.Setenv("BITBUCKET_REPO_SLUG", "myrepo")
		os.Setenv("BITBUCKET_PR_ID", "55")
		os.Unsetenv("BITBUCKET_API_URL")

		config, err := BitbucketConfigFromEnv()
		require.NoError(t, err)
		assert.Equal(t, "test-token", config.Token)
		assert.Equal(t, "myworkspace/myrepo", config.Repository)
		assert.Equal(t, 55, config.PRNumber)
		assert.Equal(t, "https://api.bitbucket.org/2.0", config.BaseURL)
	})
}

func TestFactoryCreateProvider(t *testing.T) {
	factory := NewFactory()

	t.Run("github provider", func(t *testing.T) {
		config := ProviderConfig{
			Token:      "test-token",
			Repository: "owner/repo",
			PRNumber:   123,
		}

		provider, err := factory.CreateProvider(ProviderGitHub, config)
		require.NoError(t, err)
		assert.Equal(t, ProviderGitHub, provider.Name())
		assert.Equal(t, 123, provider.PRNumber())
		assert.Equal(t, "owner/repo", provider.Repository())
	})

	t.Run("gitlab provider", func(t *testing.T) {
		config := ProviderConfig{
			Token:      "test-token",
			Repository: "group/project",
			PRNumber:   456,
		}

		provider, err := factory.CreateProvider(ProviderGitLab, config)
		require.NoError(t, err)
		assert.Equal(t, ProviderGitLab, provider.Name())
		assert.Equal(t, 456, provider.PRNumber())
		assert.Equal(t, "group/project", provider.Repository())
	})

	t.Run("bitbucket provider", func(t *testing.T) {
		config := ProviderConfig{
			Token:      "test-token",
			Repository: "workspace/repo",
			PRNumber:   789,
		}

		provider, err := factory.CreateProvider(ProviderBitbucket, config)
		require.NoError(t, err)
		assert.Equal(t, ProviderBitbucket, provider.Name())
		assert.Equal(t, 789, provider.PRNumber())
		assert.Equal(t, "workspace/repo", provider.Repository())
	})

	t.Run("unsupported provider", func(t *testing.T) {
		_, err := factory.CreateProvider("invalid", ProviderConfig{})
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUnsupportedProvider)
	})
}

func TestProviderConfigValidate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := ProviderConfig{
			Token:      "token",
			Repository: "owner/repo",
			PRNumber:   123,
		}
		assert.NoError(t, config.Validate())
	})

	t.Run("missing token", func(t *testing.T) {
		config := ProviderConfig{
			Repository: "owner/repo",
			PRNumber:   123,
		}
		assert.ErrorIs(t, config.Validate(), ErrMissingToken)
	})

	t.Run("missing repository", func(t *testing.T) {
		config := ProviderConfig{
			Token:    "token",
			PRNumber: 123,
		}
		assert.ErrorIs(t, config.Validate(), ErrMissingRepository)
	})

	t.Run("missing pr number", func(t *testing.T) {
		config := ProviderConfig{
			Token:      "token",
			Repository: "owner/repo",
		}
		assert.ErrorIs(t, config.Validate(), ErrMissingPRNumber)
	})
}
