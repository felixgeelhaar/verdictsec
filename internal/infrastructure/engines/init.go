package engines

import (
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/cyclonedx"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/gitleaks"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/gosec"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/govulncheck"
)

// NewDefaultRegistry creates a registry with all default engines pre-registered.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()

	// Register all available engines
	r.Register(gosec.NewAdapter())
	r.Register(govulncheck.NewAdapter())
	r.Register(gitleaks.NewAdapter())
	r.Register(cyclonedx.NewAdapter())

	return r
}
