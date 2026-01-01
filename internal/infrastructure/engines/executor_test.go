package engines

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEngineForExecutor for testing executor
type mockEngineForExecutor struct {
	id           ports.EngineID
	version      string
	capabilities []ports.Capability
	available    bool
	findings     []ports.RawFinding
	shouldFail   bool
	delay        time.Duration
}

func (m *mockEngineForExecutor) ID() ports.EngineID {
	return m.id
}

func (m *mockEngineForExecutor) Version() string {
	return m.version
}

func (m *mockEngineForExecutor) Capabilities() []ports.Capability {
	return m.capabilities
}

func (m *mockEngineForExecutor) IsAvailable() bool {
	return m.available
}

func (m *mockEngineForExecutor) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	// Simulate delay
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return ports.Evidence{}, nil, ctx.Err()
		}
	}

	if m.shouldFail {
		return ports.Evidence{}, nil, errors.New("engine failed")
	}
	return ports.Evidence{EngineID: m.id}, m.findings, nil
}

func TestNewExecutor(t *testing.T) {
	registry := NewRegistry()
	executor := NewExecutor(registry)

	assert.NotNil(t, executor)
	assert.Equal(t, 4, executor.maxWorkers)
}

func TestNewExecutorWithWorkers(t *testing.T) {
	registry := NewRegistry()

	executor := NewExecutorWithWorkers(registry, 8)
	assert.Equal(t, 8, executor.maxWorkers)

	// Test minimum workers
	executor2 := NewExecutorWithWorkers(registry, 0)
	assert.Equal(t, 1, executor2.maxWorkers)

	executor3 := NewExecutorWithWorkers(registry, -1)
	assert.Equal(t, 1, executor3.maxWorkers)
}

func TestExecutor_ExecuteAll(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGosec,
		available:    true,
		capabilities: []ports.Capability{ports.CapabilitySAST},
		findings: []ports.RawFinding{
			{RuleID: "G401", Message: "Test"},
		},
	})
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGovulncheck,
		available:    true,
		capabilities: []ports.Capability{ports.CapabilityVuln},
		findings: []ports.RawFinding{
			{RuleID: "GO-2023-1234", Message: "Vuln"},
		},
	})

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec:       {Enabled: true},
		ports.EngineGovulncheck: {Enabled: true},
	}

	results := executor.ExecuteAll(context.Background(), target, configs)

	assert.Len(t, results, 2)
	assert.False(t, HasErrors(results))
}

func TestExecutor_ExecuteByCapability(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGosec,
		available:    true,
		capabilities: []ports.Capability{ports.CapabilitySAST},
	})
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGovulncheck,
		available:    true,
		capabilities: []ports.Capability{ports.CapabilityVuln},
	})

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec:       {Enabled: true},
		ports.EngineGovulncheck: {Enabled: true},
	}

	results := executor.ExecuteByCapability(context.Background(), ports.CapabilitySAST, target, configs)

	assert.Len(t, results, 1)
	assert.Equal(t, ports.EngineGosec, results[0].EngineID)
}

func TestExecutor_ExecuteByCapability_SkipsDisabled(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGosec,
		available:    true,
		capabilities: []ports.Capability{ports.CapabilitySAST},
	})

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec: {Enabled: false},
	}

	results := executor.ExecuteByCapability(context.Background(), ports.CapabilitySAST, target, configs)

	assert.Len(t, results, 0)
}

func TestExecutor_ExecuteSpecific(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGosec,
		available:    true,
		capabilities: []ports.Capability{ports.CapabilitySAST},
	})
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGovulncheck,
		available:    true,
		capabilities: []ports.Capability{ports.CapabilityVuln},
	})
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGitleaks,
		available:    true,
		capabilities: []ports.Capability{ports.CapabilitySecrets},
	})

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec:       {Enabled: true},
		ports.EngineGovulncheck: {Enabled: true},
		ports.EngineGitleaks:    {Enabled: true},
	}

	results := executor.ExecuteSpecific(
		context.Background(),
		[]ports.EngineID{ports.EngineGosec, ports.EngineGitleaks},
		target,
		configs,
	)

	assert.Len(t, results, 2)

	engineIDs := make(map[ports.EngineID]bool)
	for _, r := range results {
		engineIDs[r.EngineID] = true
	}
	assert.True(t, engineIDs[ports.EngineGosec])
	assert.True(t, engineIDs[ports.EngineGitleaks])
	assert.False(t, engineIDs[ports.EngineGovulncheck])
}

func TestExecutor_ExecuteSpecific_SkipsUnavailable(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngineForExecutor{
		id:        ports.EngineGosec,
		available: false,
	})

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")

	results := executor.ExecuteSpecific(
		context.Background(),
		[]ports.EngineID{ports.EngineGosec},
		target,
		nil,
	)

	assert.Len(t, results, 0)
}

func TestExecutor_ExecuteSequential(t *testing.T) {
	registry := NewRegistry()
	engine1 := &mockEngineForExecutor{id: ports.EngineGosec, available: true}
	engine2 := &mockEngineForExecutor{id: ports.EngineGovulncheck, available: true}
	registry.Register(engine1)
	registry.Register(engine2)

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec:       {Enabled: true},
		ports.EngineGovulncheck: {Enabled: true},
	}

	results := executor.ExecuteSequential(
		context.Background(),
		[]ports.Engine{engine1, engine2},
		target,
		configs,
	)

	assert.Len(t, results, 2)
}

func TestExecutor_ExecuteSequential_SkipsDisabled(t *testing.T) {
	registry := NewRegistry()
	engine := &mockEngineForExecutor{id: ports.EngineGosec, available: true}
	registry.Register(engine)

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec: {Enabled: false},
	}

	results := executor.ExecuteSequential(
		context.Background(),
		[]ports.Engine{engine},
		target,
		configs,
	)

	assert.Len(t, results, 0)
}

func TestExecutor_HandleEngineError(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngineForExecutor{
		id:         ports.EngineGosec,
		available:  true,
		shouldFail: true,
	})

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec: {Enabled: true},
	}

	results := executor.ExecuteAll(context.Background(), target, configs)

	require.Len(t, results, 1)
	assert.NotNil(t, results[0].Error)
	assert.True(t, HasErrors(results))
}

func TestExecutor_ContextCancellation(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngineForExecutor{
		id:        ports.EngineGosec,
		available: true,
		delay:     1 * time.Second, // Slow engine
	})

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec: {Enabled: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	results := executor.ExecuteAll(ctx, target, configs)

	require.Len(t, results, 1)
	assert.NotNil(t, results[0].Error)
}

func TestHasErrors(t *testing.T) {
	resultsWithError := []ExecutionResult{
		{EngineID: ports.EngineGosec, Error: nil},
		{EngineID: ports.EngineGovulncheck, Error: errors.New("failed")},
	}

	resultsWithoutError := []ExecutionResult{
		{EngineID: ports.EngineGosec, Error: nil},
		{EngineID: ports.EngineGovulncheck, Error: nil},
	}

	assert.True(t, HasErrors(resultsWithError))
	assert.False(t, HasErrors(resultsWithoutError))
	assert.False(t, HasErrors(nil))
}

func TestGetErrors(t *testing.T) {
	err1 := errors.New("error1")
	results := []ExecutionResult{
		{EngineID: ports.EngineGosec, Error: nil},
		{EngineID: ports.EngineGovulncheck, Error: err1},
	}

	errs := GetErrors(results)

	assert.Len(t, errs, 1)
	assert.Equal(t, err1, errs[ports.EngineGovulncheck])
}

func TestGetFindings(t *testing.T) {
	results := []ExecutionResult{
		{
			EngineID: ports.EngineGosec,
			RawFindings: []ports.RawFinding{
				{RuleID: "G401"},
				{RuleID: "G402"},
			},
		},
		{
			EngineID: ports.EngineGovulncheck,
			RawFindings: []ports.RawFinding{
				{RuleID: "GO-2023-1234"},
			},
		},
		{
			EngineID: ports.EngineGitleaks,
			Error:    errors.New("failed"), // Should be skipped
		},
	}

	findings := GetFindings(results)

	assert.Len(t, findings, 3)
}

func TestGroupFindingsByEngine(t *testing.T) {
	results := []ExecutionResult{
		{
			EngineID: ports.EngineGosec,
			RawFindings: []ports.RawFinding{
				{RuleID: "G401"},
			},
		},
		{
			EngineID: ports.EngineGovulncheck,
			RawFindings: []ports.RawFinding{
				{RuleID: "GO-2023-1234"},
			},
		},
	}

	grouped := GroupFindingsByEngine(results)

	assert.Len(t, grouped, 2)
	assert.Len(t, grouped[ports.EngineGosec], 1)
	assert.Len(t, grouped[ports.EngineGovulncheck], 1)
}

func TestExecutor_EmptyEngineList(t *testing.T) {
	registry := NewRegistry()
	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")

	results := executor.ExecuteAll(context.Background(), target, nil)

	assert.Empty(t, results)
}

func TestExecutor_ParallelExecution(t *testing.T) {
	registry := NewRegistry()
	// Create engines with short delays to test parallelism
	for i := 0; i < 4; i++ {
		registry.Register(&mockEngineForExecutor{
			id:        ports.EngineID("engine" + string(rune('1'+i))),
			available: true,
			delay:     10 * time.Millisecond,
		})
	}

	executor := NewExecutorWithWorkers(registry, 4)
	target := ports.NewTarget("/test")
	configs := make(map[ports.EngineID]ports.EngineConfig)
	for i := 0; i < 4; i++ {
		configs[ports.EngineID("engine"+string(rune('1'+i)))] = ports.EngineConfig{Enabled: true}
	}

	start := time.Now()
	results := executor.ExecuteAll(context.Background(), target, configs)
	duration := time.Since(start)

	assert.Len(t, results, 4)
	// With parallelism, should complete faster than sequential (4 * 10ms = 40ms)
	// Allow some overhead but should be well under 40ms
	assert.Less(t, duration, 35*time.Millisecond)
}

func TestExecutor_ExecuteByCapability_NoEnginesForCapability(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGosec,
		available:    true,
		capabilities: []ports.Capability{ports.CapabilitySAST},
	})

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec: {Enabled: true},
	}

	// Request capability that no engine has
	results := executor.ExecuteByCapability(context.Background(), ports.CapabilityVuln, target, configs)

	assert.Empty(t, results)
}

func TestExecutor_ExecuteByCapability_UnavailableEngine(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockEngineForExecutor{
		id:           ports.EngineGosec,
		available:    false, // Not available
		capabilities: []ports.Capability{ports.CapabilitySAST},
	})

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec: {Enabled: true},
	}

	results := executor.ExecuteByCapability(context.Background(), ports.CapabilitySAST, target, configs)

	assert.Empty(t, results)
}

func TestExecutor_ExecuteSequential_WithError(t *testing.T) {
	registry := NewRegistry()
	engine1 := &mockEngineForExecutor{id: ports.EngineGosec, available: true}
	engine2 := &mockEngineForExecutor{id: ports.EngineGovulncheck, available: true, shouldFail: true}
	registry.Register(engine1)
	registry.Register(engine2)

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec:       {Enabled: true},
		ports.EngineGovulncheck: {Enabled: true},
	}

	results := executor.ExecuteSequential(
		context.Background(),
		[]ports.Engine{engine1, engine2},
		target,
		configs,
	)

	assert.Len(t, results, 2)
	assert.Nil(t, results[0].Error)
	assert.NotNil(t, results[1].Error)
}

func TestExecutor_ExecuteSequential_ContextCancel(t *testing.T) {
	registry := NewRegistry()
	engine := &mockEngineForExecutor{
		id:        ports.EngineGosec,
		available: true,
		delay:     100 * time.Millisecond,
	}
	registry.Register(engine)

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")
	configs := map[ports.EngineID]ports.EngineConfig{
		ports.EngineGosec: {Enabled: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	results := executor.ExecuteSequential(
		ctx,
		[]ports.Engine{engine},
		target,
		configs,
	)

	assert.Len(t, results, 1)
	assert.NotNil(t, results[0].Error)
}

func TestExecutor_ExecuteSpecific_NotRegistered(t *testing.T) {
	registry := NewRegistry()
	// Don't register any engines

	executor := NewExecutor(registry)
	target := ports.NewTarget("/test")

	results := executor.ExecuteSpecific(
		context.Background(),
		[]ports.EngineID{ports.EngineGosec},
		target,
		nil,
	)

	assert.Empty(t, results)
}
