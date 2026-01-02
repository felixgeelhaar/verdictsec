package engines

import (
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/gitleaks"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/gosec"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/govulncheck"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/staticcheck"
)

// NormalizerConfig holds severity mappings per engine.
type NormalizerConfig struct {
	GosecMappings       map[string]finding.Severity
	GovulncheckMappings map[string]finding.Severity
	GitleaksMappings    map[string]finding.Severity
	StaticcheckMappings map[string]finding.Severity
}

// CompositeNormalizer dispatches to the appropriate engine normalizer.
type CompositeNormalizer struct {
	gosecNorm       *gosec.Normalizer
	govulncheckNorm *govulncheck.Normalizer
	gitleaksNorm    *gitleaks.Normalizer
	staticcheckNorm *staticcheck.Normalizer
}

// NewCompositeNormalizer creates a normalizer that handles all engines.
func NewCompositeNormalizer() *CompositeNormalizer {
	return &CompositeNormalizer{
		gosecNorm:       gosec.NewNormalizer(),
		govulncheckNorm: govulncheck.NewNormalizer(),
		gitleaksNorm:    gitleaks.NewNormalizer(),
		staticcheckNorm: staticcheck.NewNormalizer(),
	}
}

// NewCompositeNormalizerWithConfig creates a normalizer with custom severity mappings.
func NewCompositeNormalizerWithConfig(cfg NormalizerConfig) *CompositeNormalizer {
	return &CompositeNormalizer{
		gosecNorm:       gosec.NewNormalizerWithOverrides(cfg.GosecMappings),
		govulncheckNorm: govulncheck.NewNormalizerWithOverrides(cfg.GovulncheckMappings),
		gitleaksNorm:    gitleaks.NewNormalizerWithOverrides(cfg.GitleaksMappings),
		staticcheckNorm: staticcheck.NewNormalizerWithOverrides(cfg.StaticcheckMappings),
	}
}

// NewCompositeNormalizerFromPortsConfig creates a normalizer from ports.Config.
func NewCompositeNormalizerFromPortsConfig(cfg ports.Config) *CompositeNormalizer {
	normCfg := NormalizerConfig{}

	if gosecCfg, ok := cfg.Engines[ports.EngineGosec]; ok && gosecCfg.SeverityMapping != nil {
		normCfg.GosecMappings = gosecCfg.SeverityMapping
	}
	if govulnCfg, ok := cfg.Engines[ports.EngineGovulncheck]; ok && govulnCfg.SeverityMapping != nil {
		normCfg.GovulncheckMappings = govulnCfg.SeverityMapping
	}
	if gitleaksCfg, ok := cfg.Engines[ports.EngineGitleaks]; ok && gitleaksCfg.SeverityMapping != nil {
		normCfg.GitleaksMappings = gitleaksCfg.SeverityMapping
	}
	if staticcheckCfg, ok := cfg.Engines[ports.EngineStaticcheck]; ok && staticcheckCfg.SeverityMapping != nil {
		normCfg.StaticcheckMappings = staticcheckCfg.SeverityMapping
	}

	return NewCompositeNormalizerWithConfig(normCfg)
}

// Normalize converts a raw finding to a domain finding.
// It dispatches to the appropriate engine normalizer based on engine ID.
func (n *CompositeNormalizer) Normalize(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding {
	switch engineID {
	case ports.EngineGosec:
		return n.gosecNorm.Normalize(engineID, raw)
	case ports.EngineGovulncheck:
		return n.govulncheckNorm.Normalize(engineID, raw)
	case ports.EngineGitleaks:
		return n.gitleaksNorm.Normalize(engineID, raw)
	case ports.EngineStaticcheck:
		return n.staticcheckNorm.Normalize(engineID, raw)
	case ports.EngineCycloneDX, ports.EngineSyft:
		// CycloneDX and Syft produce SBOM, not findings - return nil
		return nil
	default:
		// Unknown engine - create a basic finding
		return n.createBasicFinding(engineID, raw)
	}
}

// createBasicFinding creates a finding without engine-specific normalization.
func (n *CompositeNormalizer) createBasicFinding(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding {
	loc := finding.NewLocation(
		raw.File,
		raw.StartLine,
		raw.StartColumn,
		raw.EndLine,
		raw.EndColumn,
	)

	return finding.NewFinding(
		finding.FindingTypeSAST,
		string(engineID),
		raw.RuleID,
		raw.Message,
		finding.SeverityUnknown,
		loc,
	)
}
