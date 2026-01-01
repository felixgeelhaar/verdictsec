package mocks

import (
	"context"
	"errors"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMockEngine(t *testing.T) {
	engine := NewMockEngine(ports.EngineGosec)

	assert.Equal(t, ports.EngineGosec, engine.ID())
	assert.Equal(t, "1.0.0-mock", engine.Version())
	assert.True(t, engine.IsAvailable())
	assert.Contains(t, engine.Capabilities(), ports.CapabilitySAST)
}

func TestMockEngine_Run_DefaultEmpty(t *testing.T) {
	engine := NewMockEngine(ports.EngineGosec)

	evidence, findings, err := engine.Run(context.Background(), ports.Target{Path: "."}, ports.EngineConfig{})

	require.NoError(t, err)
	assert.Equal(t, ports.EngineGosec, evidence.EngineID)
	assert.Empty(t, findings)
}

func TestMockEngine_WithFindings(t *testing.T) {
	rawFindings := []ports.RawFinding{
		{
			RuleID:    "G401",
			Message:   "Test finding",
			Severity:  "HIGH",
			File:      "main.go",
			StartLine: 10,
		},
	}

	engine := NewMockEngine(ports.EngineGosec).WithFindings(rawFindings)

	evidence, findings, err := engine.Run(context.Background(), ports.Target{Path: "."}, ports.EngineConfig{})

	require.NoError(t, err)
	assert.Equal(t, ports.EngineGosec, evidence.EngineID)
	assert.Len(t, findings, 1)
	assert.Equal(t, "G401", findings[0].RuleID)
}

func TestMockEngine_WithError(t *testing.T) {
	expectedErr := errors.New("engine failed")
	engine := NewMockEngine(ports.EngineGosec).WithError(expectedErr)

	_, _, err := engine.Run(context.Background(), ports.Target{Path: "."}, ports.EngineConfig{})

	assert.ErrorIs(t, err, expectedErr)
}

func TestNewMockRegistry(t *testing.T) {
	registry := NewMockRegistry()

	assert.NotNil(t, registry)
	assert.Empty(t, registry.All())
}

func TestMockRegistry_Register(t *testing.T) {
	registry := NewMockRegistry()
	engine := NewMockEngine(ports.EngineGosec)

	registry.Register(engine)

	assert.Len(t, registry.All(), 1)
}

func TestMockRegistry_Get(t *testing.T) {
	registry := NewMockRegistry()
	engine := NewMockEngine(ports.EngineGosec)
	registry.Register(engine)

	found, ok := registry.Get(ports.EngineGosec)
	assert.True(t, ok)
	assert.Equal(t, ports.EngineGosec, found.ID())

	_, ok = registry.Get(ports.EngineGitleaks)
	assert.False(t, ok)
}

func TestMockRegistry_GetByCapability(t *testing.T) {
	registry := NewMockRegistry()

	sastEngine := NewMockEngine(ports.EngineGosec)
	sastEngine.CapabilitiesValue = []ports.Capability{ports.CapabilitySAST}

	vulnEngine := NewMockEngine(ports.EngineGovulncheck)
	vulnEngine.CapabilitiesValue = []ports.Capability{ports.CapabilityVuln}

	registry.Register(sastEngine)
	registry.Register(vulnEngine)

	sastEngines := registry.GetByCapability(ports.CapabilitySAST)
	assert.Len(t, sastEngines, 1)
	assert.Equal(t, ports.EngineGosec, sastEngines[0].ID())

	vulnEngines := registry.GetByCapability(ports.CapabilityVuln)
	assert.Len(t, vulnEngines, 1)
	assert.Equal(t, ports.EngineGovulncheck, vulnEngines[0].ID())
}

func TestMockRegistry_Available(t *testing.T) {
	registry := NewMockRegistry()

	availableEngine := NewMockEngine(ports.EngineGosec)
	availableEngine.IsAvailableValue = true

	unavailableEngine := NewMockEngine(ports.EngineGitleaks)
	unavailableEngine.IsAvailableValue = false

	registry.Register(availableEngine)
	registry.Register(unavailableEngine)

	available := registry.Available()
	assert.Len(t, available, 1)
	assert.Equal(t, ports.EngineGosec, available[0].ID())
}
