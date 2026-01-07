package ai

import (
	"context"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/advisory"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/ai/claude"
)

// Advisor is a facade that provides access to AI advisory services
// through the registry. It delegates to the configured provider.
type Advisor struct {
	registry ports.AdvisorRegistry
	config   ports.AdvisorConfig
}

// NewAdvisor creates a new advisor facade with the given configuration.
// It initializes the registry and registers available providers.
func NewAdvisor(config ports.AdvisorConfig) *Advisor {
	registry := NewRegistry(config)

	// Register Claude adapter if API key is available
	claudeAdapter := claude.NewAdapter(
		claude.WithModel(config.Model),
		claude.WithFeatures(config.Features),
	)
	if config.APIKey != "" {
		claudeAdapter = claude.NewAdapter(
			claude.WithAPIKey(config.APIKey),
			claude.WithModel(config.Model),
			claude.WithFeatures(config.Features),
		)
	}
	if config.BaseURL != "" {
		claudeAdapter = claude.NewAdapter(
			claude.WithAPIKey(config.APIKey),
			claude.WithBaseURL(config.BaseURL),
			claude.WithModel(config.Model),
			claude.WithFeatures(config.Features),
		)
	}
	_ = registry.Register(claudeAdapter)

	return &Advisor{
		registry: registry,
		config:   config,
	}
}

// Explain generates an explanation for a security finding.
func (a *Advisor) Explain(ctx context.Context, f *finding.Finding) (*advisory.Explanation, error) {
	advisor, err := a.registry.Default()
	if err != nil {
		return nil, err
	}
	return advisor.Explain(ctx, f)
}

// ExplainWithProvider generates an explanation using a specific provider.
func (a *Advisor) ExplainWithProvider(ctx context.Context, f *finding.Finding, provider string) (*advisory.Explanation, error) {
	advisor, err := a.registry.Get(provider)
	if err != nil {
		return nil, err
	}
	return advisor.Explain(ctx, f)
}

// Remediate generates remediation suggestions for a finding.
func (a *Advisor) Remediate(ctx context.Context, f *finding.Finding, opts ports.RemediationOptions) (*advisory.Remediation, error) {
	advisor, err := a.registry.Default()
	if err != nil {
		return nil, err
	}
	return advisor.Remediate(ctx, f, opts)
}

// RemediateWithProvider generates remediation using a specific provider.
func (a *Advisor) RemediateWithProvider(ctx context.Context, f *finding.Finding, provider string, opts ports.RemediationOptions) (*advisory.Remediation, error) {
	advisor, err := a.registry.Get(provider)
	if err != nil {
		return nil, err
	}
	return advisor.Remediate(ctx, f, opts)
}

// Summarize generates a posture summary for an assessment.
func (a *Advisor) Summarize(ctx context.Context, assess *assessment.Assessment) (*advisory.PostureSummary, error) {
	advisor, err := a.registry.Default()
	if err != nil {
		return nil, err
	}
	return advisor.Summarize(ctx, assess)
}

// SummarizeWithProvider generates a posture summary using a specific provider.
func (a *Advisor) SummarizeWithProvider(ctx context.Context, assess *assessment.Assessment, provider string) (*advisory.PostureSummary, error) {
	advisor, err := a.registry.Get(provider)
	if err != nil {
		return nil, err
	}
	return advisor.Summarize(ctx, assess)
}

// Provider returns the default provider name.
func (a *Advisor) Provider() string {
	return a.config.Provider
}

// Model returns the configured model.
func (a *Advisor) Model() string {
	return a.config.Model
}

// IsAvailable checks if the advisor is configured and available.
func (a *Advisor) IsAvailable() bool {
	if !a.registry.IsEnabled() {
		return false
	}
	advisor, err := a.registry.Default()
	if err != nil {
		return false
	}
	return advisor.IsAvailable()
}

// Registry returns the underlying registry for advanced use cases.
func (a *Advisor) Registry() ports.AdvisorRegistry {
	return a.registry
}

// Ensure Advisor can satisfy ports.Advisor (for simple use cases).
var _ ports.Advisor = (*Advisor)(nil)
