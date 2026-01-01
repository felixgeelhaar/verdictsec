// Package mocks provides mock implementations for testing.
package mocks

import (
	"context"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// MockEngine is a configurable mock implementation of ports.Engine.
type MockEngine struct {
	IDValue           ports.EngineID
	VersionValue      string
	CapabilitiesValue []ports.Capability
	IsAvailableValue  bool
	RunFunc           func(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error)
}

// NewMockEngine creates a new mock engine with default values.
func NewMockEngine(id ports.EngineID) *MockEngine {
	return &MockEngine{
		IDValue:           id,
		VersionValue:      "1.0.0-mock",
		CapabilitiesValue: []ports.Capability{ports.CapabilitySAST},
		IsAvailableValue:  true,
	}
}

// ID returns the engine ID.
func (m *MockEngine) ID() ports.EngineID {
	return m.IDValue
}

// Version returns the engine version.
func (m *MockEngine) Version() string {
	return m.VersionValue
}

// Capabilities returns the engine capabilities.
func (m *MockEngine) Capabilities() []ports.Capability {
	return m.CapabilitiesValue
}

// IsAvailable returns whether the engine is available.
func (m *MockEngine) IsAvailable() bool {
	return m.IsAvailableValue
}

// Run executes the mock scan.
func (m *MockEngine) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	if m.RunFunc != nil {
		return m.RunFunc(ctx, target, config)
	}
	// Default: return empty results
	return ports.Evidence{
		EngineID:      m.IDValue,
		EngineVersion: m.VersionValue,
		RawOutput:     []byte("{}"),
		OutputFormat:  "json",
	}, nil, nil
}

// WithFindings configures the mock to return specific raw findings.
func (m *MockEngine) WithFindings(findings []ports.RawFinding) *MockEngine {
	m.RunFunc = func(_ context.Context, _ ports.Target, _ ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
		return ports.Evidence{
			EngineID:      m.IDValue,
			EngineVersion: m.VersionValue,
			RawOutput:     []byte("{}"),
			OutputFormat:  "json",
		}, findings, nil
	}
	return m
}

// WithError configures the mock to return an error.
func (m *MockEngine) WithError(err error) *MockEngine {
	m.RunFunc = func(_ context.Context, _ ports.Target, _ ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
		return ports.Evidence{}, nil, err
	}
	return m
}

// MockRegistry is a mock implementation of ports.EngineRegistry.
type MockRegistry struct {
	engines map[ports.EngineID]ports.Engine
}

// NewMockRegistry creates a new mock registry.
func NewMockRegistry() *MockRegistry {
	return &MockRegistry{
		engines: make(map[ports.EngineID]ports.Engine),
	}
}

// Register adds an engine to the registry.
func (r *MockRegistry) Register(engine ports.Engine) {
	r.engines[engine.ID()] = engine
}

// Get returns an engine by ID.
func (r *MockRegistry) Get(id ports.EngineID) (ports.Engine, bool) {
	e, ok := r.engines[id]
	return e, ok
}

// GetByCapability returns engines with a specific capability.
func (r *MockRegistry) GetByCapability(cap ports.Capability) []ports.Engine {
	var result []ports.Engine
	for _, e := range r.engines {
		for _, c := range e.Capabilities() {
			if c == cap {
				result = append(result, e)
				break
			}
		}
	}
	return result
}

// All returns all registered engines.
func (r *MockRegistry) All() []ports.Engine {
	result := make([]ports.Engine, 0, len(r.engines))
	for _, e := range r.engines {
		result = append(result, e)
	}
	return result
}

// Available returns only available engines.
func (r *MockRegistry) Available() []ports.Engine {
	var result []ports.Engine
	for _, e := range r.engines {
		if e.IsAvailable() {
			result = append(result, e)
		}
	}
	return result
}
