package ports

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func TestNewTarget(t *testing.T) {
	target := NewTarget("/path/to/project", "vendor", "testdata")

	assert.Equal(t, "/path/to/project", target.Path)
	assert.Equal(t, []string{"vendor", "testdata"}, target.Exclusions)
}

func TestNewTarget_NoExclusions(t *testing.T) {
	target := NewTarget("/path/to/project")

	assert.Equal(t, "/path/to/project", target.Path)
	assert.Empty(t, target.Exclusions)
}

func TestDefaultEngineConfig(t *testing.T) {
	cfg := DefaultEngineConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, finding.SeverityLow, cfg.MinSeverity)
	assert.Empty(t, cfg.ExcludeIDs)
	assert.NotNil(t, cfg.Settings)
}

func TestEngineID_Constants(t *testing.T) {
	assert.Equal(t, EngineID("gosec"), EngineGosec)
	assert.Equal(t, EngineID("govulncheck"), EngineGovulncheck)
	assert.Equal(t, EngineID("gitleaks"), EngineGitleaks)
	assert.Equal(t, EngineID("cyclonedx-gomod"), EngineCycloneDX)
	assert.Equal(t, EngineID("syft"), EngineSyft)
}

func TestCapability_Constants(t *testing.T) {
	assert.Equal(t, Capability("sast"), CapabilitySAST)
	assert.Equal(t, Capability("vuln"), CapabilityVuln)
	assert.Equal(t, Capability("secrets"), CapabilitySecrets)
	assert.Equal(t, Capability("sbom"), CapabilitySBOM)
}
