package ports

import (
	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
)

// BaselineStore defines the interface for baseline persistence.
type BaselineStore interface {
	// Load reads the baseline from the default location.
	// Returns nil baseline if no baseline file exists.
	Load() (*baseline.Baseline, error)

	// LoadFrom reads the baseline from a specific path.
	LoadFrom(path string) (*baseline.Baseline, error)

	// Save writes the baseline to the default location.
	Save(b *baseline.Baseline) error

	// SaveTo writes the baseline to a specific path.
	SaveTo(b *baseline.Baseline, path string) error

	// Exists checks if a baseline file exists at the default location.
	Exists() bool

	// DefaultPath returns the default baseline file path.
	DefaultPath() string
}

// BaselineOptions configures baseline behavior.
type BaselineOptions struct {
	// Path overrides the default baseline location.
	Path string

	// StrictMode fails on baselined findings too.
	StrictMode bool

	// AutoUpdate automatically updates baseline after successful scan.
	AutoUpdate bool

	// PruneAfterDays removes entries not seen for this many days.
	// 0 means never prune.
	PruneAfterDays int
}

// DefaultBaselineOptions returns sensible defaults.
func DefaultBaselineOptions() BaselineOptions {
	return BaselineOptions{
		Path:           "",
		StrictMode:     false,
		AutoUpdate:     false,
		PruneAfterDays: 0,
	}
}
