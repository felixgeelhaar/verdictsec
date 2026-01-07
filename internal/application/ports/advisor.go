package ports

import (
	"context"

	"github.com/felixgeelhaar/verdictsec/internal/domain/advisory"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Advisor defines the interface for AI-powered security advisory services.
// All methods are read-only and produce advisory-only output that cannot
// modify findings, decisions, or policy.
type Advisor interface {
	// Explain generates an explanation for a security finding.
	Explain(ctx context.Context, finding *finding.Finding) (*advisory.Explanation, error)

	// Remediate generates remediation suggestions for a finding.
	Remediate(ctx context.Context, finding *finding.Finding, opts RemediationOptions) (*advisory.Remediation, error)

	// Summarize generates a posture summary for an assessment.
	Summarize(ctx context.Context, assessment *assessment.Assessment) (*advisory.PostureSummary, error)

	// Provider returns the provider name (e.g., "claude", "openai").
	Provider() string

	// Model returns the model ID in use.
	Model() string

	// IsAvailable checks if the advisor is configured and available.
	IsAvailable() bool
}

// RemediationOptions configures remediation generation.
type RemediationOptions struct {
	// IncludeCode requests code suggestions when true.
	IncludeCode bool

	// MaxSuggestions limits the number of code suggestions.
	MaxSuggestions int

	// Context provides additional context for remediation.
	Context string
}

// AdvisorRegistry manages multiple advisor implementations.
type AdvisorRegistry interface {
	// Register adds an advisor implementation.
	Register(advisor Advisor) error

	// Get returns the advisor for a provider, or the default if empty.
	Get(provider string) (Advisor, error)

	// Default returns the default configured advisor.
	Default() (Advisor, error)

	// List returns all registered provider names.
	List() []string

	// IsEnabled returns true if AI advisory is enabled.
	IsEnabled() bool
}

// AdvisorConfig holds AI advisor configuration.
type AdvisorConfig struct {
	// Enabled controls whether AI features are available.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Provider is the default AI provider (claude, openai, local).
	Provider string `yaml:"provider" json:"provider"`

	// Model is the model ID to use.
	Model string `yaml:"model" json:"model"`

	// APIKey is the API key (can also be set via environment).
	APIKey string `yaml:"api_key,omitempty" json:"api_key,omitempty"`

	// BaseURL is an optional custom API endpoint.
	BaseURL string `yaml:"base_url,omitempty" json:"base_url,omitempty"`

	// Features controls which AI features are enabled.
	Features AdvisorFeatures `yaml:"features" json:"features"`

	// RateLimits configures rate limiting.
	RateLimits RateLimits `yaml:"rate_limits,omitempty" json:"rate_limits,omitempty"`
}

// AdvisorFeatures controls which AI features are enabled.
type AdvisorFeatures struct {
	// Explain enables finding explanations.
	Explain bool `yaml:"explain" json:"explain"`

	// Remediate enables remediation suggestions.
	Remediate bool `yaml:"remediate" json:"remediate"`

	// Summarize enables posture summaries.
	Summarize bool `yaml:"summarize" json:"summarize"`
}

// RateLimits configures API rate limiting.
type RateLimits struct {
	// RequestsPerMinute limits API calls per minute.
	RequestsPerMinute int `yaml:"requests_per_minute,omitempty" json:"requests_per_minute,omitempty"`

	// MaxTokensPerRequest limits tokens per request.
	MaxTokensPerRequest int `yaml:"max_tokens_per_request,omitempty" json:"max_tokens_per_request,omitempty"`
}

// DefaultAdvisorConfig returns sensible defaults for AI configuration.
func DefaultAdvisorConfig() AdvisorConfig {
	return AdvisorConfig{
		Enabled:  false, // Opt-in by default
		Provider: "claude",
		Model:    "claude-3-5-sonnet-20241022",
		Features: AdvisorFeatures{
			Explain:   true,
			Remediate: true,
			Summarize: true,
		},
		RateLimits: RateLimits{
			RequestsPerMinute:   60,
			MaxTokensPerRequest: 4096,
		},
	}
}

// AdvisorWriter writes advisory output.
type AdvisorWriter interface {
	// WriteExplanation writes an explanation to the output.
	WriteExplanation(explanation *advisory.Explanation) error

	// WriteRemediation writes a remediation to the output.
	WriteRemediation(remediation *advisory.Remediation) error

	// WritePostureSummary writes a posture summary to the output.
	WritePostureSummary(summary *advisory.PostureSummary) error

	// Flush ensures all output is written.
	Flush() error
}

// ErrAdvisorNotEnabled is returned when AI features are disabled.
type ErrAdvisorNotEnabled struct{}

func (e ErrAdvisorNotEnabled) Error() string {
	return "AI advisor is not enabled; set ai.enabled: true in config"
}

// ErrProviderNotFound is returned when a provider is not registered.
type ErrProviderNotFound struct {
	Provider string
}

func (e ErrProviderNotFound) Error() string {
	return "AI provider not found: " + e.Provider
}

// ErrFeatureDisabled is returned when a specific feature is disabled.
type ErrFeatureDisabled struct {
	Feature string
}

func (e ErrFeatureDisabled) Error() string {
	return "AI feature disabled: " + e.Feature
}
