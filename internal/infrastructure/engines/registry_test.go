package engines

import (
	"context"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEngine for testing
type mockEngine struct {
	id           ports.EngineID
	version      string
	capabilities []ports.Capability
	available    bool
}

func (m *mockEngine) ID() ports.EngineID {
	return m.id
}

func (m *mockEngine) Version() string {
	return m.version
}

func (m *mockEngine) Capabilities() []ports.Capability {
	return m.capabilities
}

func (m *mockEngine) IsAvailable() bool {
	return m.available
}

func (m *mockEngine) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	return ports.Evidence{EngineID: m.id}, nil, nil
}

func TestNewRegistry(t *testing.T) {
	registry := NewRegistry()

	assert.NotNil(t, registry)
	assert.NotNil(t, registry.engines)
	assert.Equal(t, 0, registry.Count())
}

func TestRegistry_Register(t *testing.T) {
	registry := NewRegistry()
	engine := &mockEngine{id: ports.EngineGosec, version: "1.0.0"}

	registry.Register(engine)

	assert.Equal(t, 1, registry.Count())
}

func TestRegistry_Register_Override(t *testing.T) {
	registry := NewRegistry()
	engine1 := &mockEngine{id: ports.EngineGosec, version: "1.0.0"}
	engine2 := &mockEngine{id: ports.EngineGosec, version: "2.0.0"}

	registry.Register(engine1)
	registry.Register(engine2)

	// Should override with second registration
	assert.Equal(t, 1, registry.Count())

	e, ok := registry.Get(ports.EngineGosec)
	require.True(t, ok)
	assert.Equal(t, "2.0.0", e.Version())
}

func TestRegistry_Get(t *testing.T) {
	registry := NewRegistry()
	engine := &mockEngine{id: ports.EngineGosec, version: "1.0.0"}
	registry.Register(engine)

	result, ok := registry.Get(ports.EngineGosec)

	assert.True(t, ok)
	assert.Equal(t, ports.EngineGosec, result.ID())
}

func TestRegistry_Get_NotFound(t *testing.T) {
	registry := NewRegistry()

	result, ok := registry.Get(ports.EngineGosec)

	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestRegistry_GetByCapability(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    true,
	})
	registry.Register(&mockEngine{
		id:           ports.EngineGovulncheck,
		capabilities: []ports.Capability{ports.CapabilityVuln},
		available:    true,
	})
	registry.Register(&mockEngine{
		id:           ports.EngineGitleaks,
		capabilities: []ports.Capability{ports.CapabilitySecrets},
		available:    true,
	})

	sastEngines := registry.GetByCapability(ports.CapabilitySAST)
	vulnEngines := registry.GetByCapability(ports.CapabilityVuln)
	secretsEngines := registry.GetByCapability(ports.CapabilitySecrets)

	assert.Len(t, sastEngines, 1)
	assert.Equal(t, ports.EngineGosec, sastEngines[0].ID())

	assert.Len(t, vulnEngines, 1)
	assert.Equal(t, ports.EngineGovulncheck, vulnEngines[0].ID())

	assert.Len(t, secretsEngines, 1)
	assert.Equal(t, ports.EngineGitleaks, secretsEngines[0].ID())
}

func TestRegistry_GetByCapability_NoMatch(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		capabilities: []ports.Capability{ports.CapabilitySAST},
	})

	engines := registry.GetByCapability(ports.CapabilityVuln)

	assert.Empty(t, engines)
}

func TestRegistry_GetByCapability_MultipleCapabilities(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		capabilities: []ports.Capability{ports.CapabilitySAST, ports.CapabilityVuln},
	})

	sastEngines := registry.GetByCapability(ports.CapabilitySAST)
	vulnEngines := registry.GetByCapability(ports.CapabilityVuln)

	assert.Len(t, sastEngines, 1)
	assert.Len(t, vulnEngines, 1)
	assert.Equal(t, ports.EngineGosec, sastEngines[0].ID())
	assert.Equal(t, ports.EngineGosec, vulnEngines[0].ID())
}

func TestRegistry_All(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{id: ports.EngineGosec})
	registry.Register(&mockEngine{id: ports.EngineGovulncheck})
	registry.Register(&mockEngine{id: ports.EngineGitleaks})

	all := registry.All()

	assert.Len(t, all, 3)
}

func TestRegistry_All_Empty(t *testing.T) {
	registry := NewRegistry()

	all := registry.All()

	assert.Empty(t, all)
}

func TestRegistry_Available(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{id: ports.EngineGosec, available: true})
	registry.Register(&mockEngine{id: ports.EngineGovulncheck, available: false})
	registry.Register(&mockEngine{id: ports.EngineGitleaks, available: true})

	available := registry.Available()

	assert.Len(t, available, 2)
}

func TestRegistry_Available_NoneAvailable(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{id: ports.EngineGosec, available: false})
	registry.Register(&mockEngine{id: ports.EngineGovulncheck, available: false})

	available := registry.Available()

	assert.Empty(t, available)
}

func TestRegistry_Count(t *testing.T) {
	registry := NewRegistry()

	assert.Equal(t, 0, registry.Count())

	registry.Register(&mockEngine{id: ports.EngineGosec})
	assert.Equal(t, 1, registry.Count())

	registry.Register(&mockEngine{id: ports.EngineGovulncheck})
	assert.Equal(t, 2, registry.Count())
}

func TestRegistry_AvailableCount(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{id: ports.EngineGosec, available: true})
	registry.Register(&mockEngine{id: ports.EngineGovulncheck, available: false})
	registry.Register(&mockEngine{id: ports.EngineGitleaks, available: true})

	count := registry.AvailableCount()

	assert.Equal(t, 2, count)
}

func TestRegistry_IDs(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{id: ports.EngineGosec})
	registry.Register(&mockEngine{id: ports.EngineGovulncheck})

	ids := registry.IDs()

	assert.Len(t, ids, 2)
	assert.Contains(t, ids, ports.EngineGosec)
	assert.Contains(t, ids, ports.EngineGovulncheck)
}

func TestRegistry_IDs_Empty(t *testing.T) {
	registry := NewRegistry()

	ids := registry.IDs()

	assert.Empty(t, ids)
}

func TestRegistry_Unregister(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{id: ports.EngineGosec})

	removed := registry.Unregister(ports.EngineGosec)

	assert.True(t, removed)
	assert.Equal(t, 0, registry.Count())
}

func TestRegistry_Unregister_NotFound(t *testing.T) {
	registry := NewRegistry()

	removed := registry.Unregister(ports.EngineGosec)

	assert.False(t, removed)
}

func TestRegistry_Clear(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngine{id: ports.EngineGosec})
	registry.Register(&mockEngine{id: ports.EngineGovulncheck})
	registry.Register(&mockEngine{id: ports.EngineGitleaks})

	registry.Clear()

	assert.Equal(t, 0, registry.Count())
}

func TestRegistry_ImplementsInterface(t *testing.T) {
	var _ ports.EngineRegistry = (*Registry)(nil)
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewRegistry()

	// Register engines concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id ports.EngineID) {
			registry.Register(&mockEngine{id: id})
			done <- true
		}(ports.EngineID("engine" + string(rune('0'+i))))
	}

	// Wait for all registrations
	for i := 0; i < 10; i++ {
		<-done
	}

	// Read concurrently
	for i := 0; i < 10; i++ {
		go func() {
			_ = registry.All()
			_ = registry.Available()
			_ = registry.Count()
			done <- true
		}()
	}

	// Wait for all reads
	for i := 0; i < 10; i++ {
		<-done
	}

	// Registry should have 10 engines
	assert.Equal(t, 10, registry.Count())
}
