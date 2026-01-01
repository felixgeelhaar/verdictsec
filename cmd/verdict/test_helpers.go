package main

import (
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
)

// DefaultTestConfig returns a config suitable for testing.
func DefaultTestConfig() *config.Config {
	return config.DefaultConfig()
}
