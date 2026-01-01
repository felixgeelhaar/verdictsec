package engines

import (
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/gitleaks"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/gosec"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/govulncheck"
)

// CompositeNormalizer dispatches to the appropriate engine normalizer.
type CompositeNormalizer struct {
	gosecNorm       *gosec.Normalizer
	govulncheckNorm *govulncheck.Normalizer
	gitleaksNorm    *gitleaks.Normalizer
}

// NewCompositeNormalizer creates a normalizer that handles all engines.
func NewCompositeNormalizer() *CompositeNormalizer {
	return &CompositeNormalizer{
		gosecNorm:       gosec.NewNormalizer(),
		govulncheckNorm: govulncheck.NewNormalizer(),
		gitleaksNorm:    gitleaks.NewNormalizer(),
	}
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
	case ports.EngineCycloneDX:
		// CycloneDX produces SBOM, not findings - return nil
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
