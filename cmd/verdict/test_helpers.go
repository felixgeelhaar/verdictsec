package main

import (
	"os/exec"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
)

// DefaultTestConfig returns a config suitable for testing.
func DefaultTestConfig() *config.Config {
	return config.DefaultConfig()
}

// SkipIfNoEngines skips the test if no security engines are available.
func SkipIfNoEngines(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gosec"); err != nil {
		t.Skip("Skipping test: gosec not installed")
	}
}
