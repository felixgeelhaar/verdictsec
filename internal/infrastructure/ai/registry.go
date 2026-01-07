package ai

import (
	"sync"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// Registry implements ports.AdvisorRegistry with thread-safe provider management.
type Registry struct {
	mu             sync.RWMutex
	advisors       map[string]ports.Advisor
	defaultProvider string
	enabled        bool
}

// NewRegistry creates a new advisor registry.
func NewRegistry(config ports.AdvisorConfig) *Registry {
	return &Registry{
		advisors:       make(map[string]ports.Advisor),
		defaultProvider: config.Provider,
		enabled:        config.Enabled,
	}
}

// Register adds an advisor implementation to the registry.
func (r *Registry) Register(advisor ports.Advisor) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.advisors[advisor.Provider()] = advisor
	return nil
}

// Get returns the advisor for a provider, or the default if provider is empty.
func (r *Registry) Get(provider string) (ports.Advisor, error) {
	if !r.enabled {
		return nil, ports.ErrAdvisorNotEnabled{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if provider == "" {
		provider = r.defaultProvider
	}

	advisor, ok := r.advisors[provider]
	if !ok {
		return nil, ports.ErrProviderNotFound{Provider: provider}
	}

	return advisor, nil
}

// Default returns the default configured advisor.
func (r *Registry) Default() (ports.Advisor, error) {
	return r.Get("")
}

// List returns all registered provider names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]string, 0, len(r.advisors))
	for name := range r.advisors {
		providers = append(providers, name)
	}
	return providers
}

// IsEnabled returns true if AI advisory is enabled.
func (r *Registry) IsEnabled() bool {
	return r.enabled
}

// SetEnabled enables or disables AI features.
func (r *Registry) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
}

// SetDefault sets the default provider.
func (r *Registry) SetDefault(provider string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.advisors[provider]; !ok {
		return ports.ErrProviderNotFound{Provider: provider}
	}

	r.defaultProvider = provider
	return nil
}

// Ensure Registry implements the interface.
var _ ports.AdvisorRegistry = (*Registry)(nil)
