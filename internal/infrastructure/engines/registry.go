package engines

import (
	"sync"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// Registry manages available security scanner engines.
// It implements ports.EngineRegistry.
type Registry struct {
	mu      sync.RWMutex
	engines map[ports.EngineID]ports.Engine
}

// NewRegistry creates a new engine registry.
func NewRegistry() *Registry {
	return &Registry{
		engines: make(map[ports.EngineID]ports.Engine),
	}
}

// Register adds an engine to the registry.
func (r *Registry) Register(engine ports.Engine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.engines[engine.ID()] = engine
}

// Get returns an engine by ID.
func (r *Registry) Get(id ports.EngineID) (ports.Engine, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	engine, ok := r.engines[id]
	return engine, ok
}

// GetByCapability returns all engines with a specific capability.
func (r *Registry) GetByCapability(cap ports.Capability) []ports.Engine {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []ports.Engine
	for _, engine := range r.engines {
		for _, c := range engine.Capabilities() {
			if c == cap {
				result = append(result, engine)
				break
			}
		}
	}
	return result
}

// All returns all registered engines.
func (r *Registry) All() []ports.Engine {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]ports.Engine, 0, len(r.engines))
	for _, engine := range r.engines {
		result = append(result, engine)
	}
	return result
}

// Available returns only engines that are installed and available.
func (r *Registry) Available() []ports.Engine {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []ports.Engine
	for _, engine := range r.engines {
		if engine.IsAvailable() {
			result = append(result, engine)
		}
	}
	return result
}

// Unavailable returns engines that are NOT installed or accessible.
func (r *Registry) Unavailable() []ports.Engine {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []ports.Engine
	for _, engine := range r.engines {
		if !engine.IsAvailable() {
			result = append(result, engine)
		}
	}
	return result
}

// EngineStatus represents the status of an engine for diagnostics.
type EngineStatus struct {
	Info      ports.EngineInfo
	Available bool
	Version   string // Empty if not available
	Enabled   bool   // From config
}

// Status returns the status of all registered engines.
func (r *Registry) Status(cfg ports.Config) []EngineStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]EngineStatus, 0, len(r.engines))
	for _, engine := range r.engines {
		info := engine.Info()
		available := engine.IsAvailable()

		version := ""
		if available {
			version = engine.Version()
		}

		// Check if engine is enabled in config
		enabled := true // Default to enabled if not in config
		if engineCfg, ok := cfg.Engines[engine.ID()]; ok {
			enabled = engineCfg.Enabled
		}

		result = append(result, EngineStatus{
			Info:      info,
			Available: available,
			Version:   version,
			Enabled:   enabled,
		})
	}
	return result
}

// Count returns the total number of registered engines.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.engines)
}

// AvailableCount returns the number of available engines.
func (r *Registry) AvailableCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, engine := range r.engines {
		if engine.IsAvailable() {
			count++
		}
	}
	return count
}

// IDs returns all registered engine IDs.
func (r *Registry) IDs() []ports.EngineID {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]ports.EngineID, 0, len(r.engines))
	for id := range r.engines {
		ids = append(ids, id)
	}
	return ids
}

// Unregister removes an engine from the registry.
func (r *Registry) Unregister(id ports.EngineID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.engines[id]; exists {
		delete(r.engines, id)
		return true
	}
	return false
}

// Clear removes all engines from the registry.
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.engines = make(map[ports.EngineID]ports.Engine)
}

// Ensure Registry implements ports.EngineRegistry
var _ ports.EngineRegistry = (*Registry)(nil)
