package engines

import (
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/cyclonedx"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/gitleaks"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/gosec"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/govulncheck"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/staticcheck"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/syft"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines/trivy"
)

// NewDefaultRegistry creates a registry with all default engines pre-registered.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()

	// Register all available engines
	r.Register(gosec.NewAdapter())
	r.Register(govulncheck.NewAdapter())
	r.Register(gitleaks.NewAdapter())
	r.Register(cyclonedx.NewAdapter())
	r.Register(syft.NewAdapter())
	r.Register(staticcheck.NewAdapter())
	r.Register(trivy.NewAdapter())

	return r
}
