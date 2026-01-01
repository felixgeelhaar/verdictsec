package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

// mockEngine implements ports.Engine
type mockEngine struct {
	id           ports.EngineID
	version      string
	capabilities []ports.Capability
	available    bool
	rawFindings  []ports.RawFinding
	shouldFail   bool
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

func (m *mockEngine) Info() ports.EngineInfo {
	capability := ports.CapabilitySAST
	if len(m.capabilities) > 0 {
		capability = m.capabilities[0]
	}
	return ports.EngineInfo{
		ID:          m.id,
		Name:        string(m.id),
		Description: "Mock engine for testing",
		InstallCmd:  "go install mock@latest",
		Homepage:    "https://example.com",
		Capability:  capability,
	}
}

func (m *mockEngine) Run(ctx context.Context, target ports.Target, config ports.EngineConfig) (ports.Evidence, []ports.RawFinding, error) {
	if m.shouldFail {
		return ports.Evidence{}, nil, errors.New("engine failed")
	}
	return ports.Evidence{
		EngineID:      m.id,
		EngineVersion: m.version,
	}, m.rawFindings, nil
}

// mockEngineRegistry implements ports.EngineRegistry
type mockEngineRegistry struct {
	engines map[ports.EngineID]ports.Engine
}

func newMockEngineRegistry() *mockEngineRegistry {
	return &mockEngineRegistry{
		engines: make(map[ports.EngineID]ports.Engine),
	}
}

func (m *mockEngineRegistry) Register(engine ports.Engine) {
	m.engines[engine.ID()] = engine
}

func (m *mockEngineRegistry) Get(id ports.EngineID) (ports.Engine, bool) {
	e, ok := m.engines[id]
	return e, ok
}

func (m *mockEngineRegistry) GetByCapability(cap ports.Capability) []ports.Engine {
	var result []ports.Engine
	for _, e := range m.engines {
		for _, c := range e.Capabilities() {
			if c == cap {
				result = append(result, e)
				break
			}
		}
	}
	return result
}

func (m *mockEngineRegistry) All() []ports.Engine {
	var result []ports.Engine
	for _, e := range m.engines {
		result = append(result, e)
	}
	return result
}

func (m *mockEngineRegistry) Available() []ports.Engine {
	var result []ports.Engine
	for _, e := range m.engines {
		if e.IsAvailable() {
			result = append(result, e)
		}
	}
	return result
}

// mockNormalizer implements FindingNormalizer
type mockNormalizer struct{}

func (m *mockNormalizer) Normalize(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding {
	loc := finding.NewLocation(raw.File, raw.StartLine, raw.StartColumn, raw.EndLine, raw.EndColumn)

	var sev finding.Severity
	switch raw.Severity {
	case "HIGH":
		sev = finding.SeverityHigh
	case "MEDIUM":
		sev = finding.SeverityMedium
	case "LOW":
		sev = finding.SeverityLow
	default:
		sev = finding.SeverityUnknown
	}

	return finding.NewFinding(finding.FindingTypeSAST, string(engineID), raw.RuleID, raw.Message, sev, loc)
}

func TestNewRunScanUseCase(t *testing.T) {
	registry := newMockEngineRegistry()
	normalizer := &mockNormalizer{}

	uc := NewRunScanUseCase(registry, normalizer, nil)

	assert.NotNil(t, uc)
}

func TestRunScanUseCase_Execute_NoEngines(t *testing.T) {
	registry := newMockEngineRegistry()
	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	_, err := uc.Execute(context.Background(), RunScanInput{
		Target: ports.NewTarget("/test"),
		Config: ports.DefaultConfig(),
	})

	assert.Error(t, err)
}

func TestRunScanUseCase_Execute_SingleEngine(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		version:      "2.18.0",
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    true,
		rawFindings: []ports.RawFinding{
			{
				RuleID:      "G401",
				Message:     "Use of weak crypto",
				Severity:    "HIGH",
				File:        "main.go",
				StartLine:   10,
				StartColumn: 1,
				EndLine:     10,
				EndColumn:   20,
			},
		},
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	output, err := uc.Execute(context.Background(), RunScanInput{
		Target: ports.NewTarget("/test"),
		Config: ports.DefaultConfig(),
	})

	assert.NoError(t, err)
	assert.NotNil(t, output.Assessment)
	assert.Equal(t, 1, output.Assessment.FindingCount())
	assert.Empty(t, output.Errors)
}

func TestRunScanUseCase_Execute_EngineError(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		version:      "2.18.0",
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    true,
		shouldFail:   true,
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	output, err := uc.Execute(context.Background(), RunScanInput{
		Target: ports.NewTarget("/test"),
		Config: ports.DefaultConfig(),
	})

	assert.NoError(t, err) // Use case doesn't fail, just records error
	assert.Len(t, output.Errors, 1)
	assert.Equal(t, ports.EngineGosec, output.Errors[0].EngineID)
}

func TestRunScanUseCase_Execute_MultipleEngines(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		version:      "2.18.0",
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    true,
		rawFindings: []ports.RawFinding{
			{RuleID: "G401", Severity: "HIGH", File: "main.go", StartLine: 10, StartColumn: 1, EndLine: 10, EndColumn: 20},
		},
	})
	registry.Register(&mockEngine{
		id:           ports.EngineGovulncheck,
		version:      "1.0.0",
		capabilities: []ports.Capability{ports.CapabilityVuln},
		available:    true,
		rawFindings: []ports.RawFinding{
			{RuleID: "CVE-2024-1234", Severity: "MEDIUM", File: "go.mod", StartLine: 5, StartColumn: 1, EndLine: 5, EndColumn: 30},
		},
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	output, err := uc.Execute(context.Background(), RunScanInput{
		Target: ports.NewTarget("/test"),
		Config: ports.DefaultConfig(),
	})

	assert.NoError(t, err)
	assert.Equal(t, 2, output.Assessment.FindingCount())
}

func TestRunScanUseCase_Execute_SpecificEngines(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		version:      "2.18.0",
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    true,
		rawFindings: []ports.RawFinding{
			{RuleID: "G401", Severity: "HIGH", File: "main.go", StartLine: 10, StartColumn: 1, EndLine: 10, EndColumn: 20},
		},
	})
	registry.Register(&mockEngine{
		id:           ports.EngineGovulncheck,
		version:      "1.0.0",
		capabilities: []ports.Capability{ports.CapabilityVuln},
		available:    true,
		rawFindings: []ports.RawFinding{
			{RuleID: "CVE-2024-1234", Severity: "MEDIUM", File: "go.mod", StartLine: 5, StartColumn: 1, EndLine: 5, EndColumn: 30},
		},
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	// Only run gosec
	output, err := uc.Execute(context.Background(), RunScanInput{
		Target:  ports.NewTarget("/test"),
		Config:  ports.DefaultConfig(),
		Engines: []ports.EngineID{ports.EngineGosec},
	})

	assert.NoError(t, err)
	assert.Equal(t, 1, output.Assessment.FindingCount())
}

func TestRunScanUseCase_Execute_ParallelMode(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		version:      "2.18.0",
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    true,
		rawFindings:  []ports.RawFinding{},
	})
	registry.Register(&mockEngine{
		id:           ports.EngineGovulncheck,
		version:      "1.0.0",
		capabilities: []ports.Capability{ports.CapabilityVuln},
		available:    true,
		rawFindings:  []ports.RawFinding{},
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	output, err := uc.Execute(context.Background(), RunScanInput{
		Target:     ports.NewTarget("/test"),
		Config:     ports.DefaultConfig(),
		Parallel:   true,
		MaxWorkers: 2,
	})

	assert.NoError(t, err)
	assert.NotNil(t, output.Assessment)
	assert.True(t, output.Assessment.IsCompleted())
}

func TestRunScanUseCase_Execute_ContextCancellation(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		version:      "2.18.0",
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    true,
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	output, err := uc.Execute(ctx, RunScanInput{
		Target: ports.NewTarget("/test"),
		Config: ports.DefaultConfig(),
	})

	assert.NoError(t, err)
	assert.NotNil(t, output.Assessment)
}

func TestRunScanUseCase_Execute_UnavailableEngine(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		version:      "2.18.0",
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    false, // Not installed
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	_, err := uc.Execute(context.Background(), RunScanInput{
		Target: ports.NewTarget("/test"),
		Config: ports.DefaultConfig(),
	})

	assert.Error(t, err) // No available engines
}

func TestRunScanUseCase_RunSAST(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		version:      "2.18.0",
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    true,
		rawFindings:  []ports.RawFinding{},
	})
	registry.Register(&mockEngine{
		id:           ports.EngineGovulncheck,
		version:      "1.0.0",
		capabilities: []ports.Capability{ports.CapabilityVuln}, // Not SAST
		available:    true,
		rawFindings:  []ports.RawFinding{},
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	output, err := uc.RunSAST(context.Background(), RunSASTInput{
		Target: ports.NewTarget("/test"),
		Config: ports.DefaultConfig(),
	})

	assert.NoError(t, err)
	assert.NotNil(t, output.Assessment)
}

func TestRunScanUseCase_RunVuln(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGovulncheck,
		version:      "1.0.0",
		capabilities: []ports.Capability{ports.CapabilityVuln},
		available:    true,
		rawFindings:  []ports.RawFinding{},
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	output, err := uc.RunVuln(context.Background(), RunVulnInput{
		Target: ports.NewTarget("/test"),
		Config: ports.DefaultConfig(),
	})

	assert.NoError(t, err)
	assert.NotNil(t, output.Assessment)
}

func TestRunScanUseCase_RunSecrets(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGitleaks,
		version:      "8.18.0",
		capabilities: []ports.Capability{ports.CapabilitySecrets},
		available:    true,
		rawFindings:  []ports.RawFinding{},
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	output, err := uc.RunSecrets(context.Background(), RunSecretsInput{
		Target: ports.NewTarget("/test"),
		Config: ports.DefaultConfig(),
	})

	assert.NoError(t, err)
	assert.NotNil(t, output.Assessment)
}

func TestRunScanUseCase_Execute_DisabledEngine(t *testing.T) {
	registry := newMockEngineRegistry()
	registry.Register(&mockEngine{
		id:           ports.EngineGosec,
		version:      "2.18.0",
		capabilities: []ports.Capability{ports.CapabilitySAST},
		available:    true,
	})

	normalizer := &mockNormalizer{}
	uc := NewRunScanUseCase(registry, normalizer, nil)

	// Disable gosec
	cfg := ports.DefaultConfig()
	gosecCfg := cfg.Engines[ports.EngineGosec]
	gosecCfg.Enabled = false
	cfg.Engines[ports.EngineGosec] = gosecCfg

	_, err := uc.Execute(context.Background(), RunScanInput{
		Target: ports.NewTarget("/test"),
		Config: cfg,
	})

	assert.Error(t, err) // No enabled engines
}
