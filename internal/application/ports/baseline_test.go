package ports

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultBaselineOptions(t *testing.T) {
	opts := DefaultBaselineOptions()

	assert.Empty(t, opts.Path)
	assert.False(t, opts.StrictMode)
	assert.False(t, opts.AutoUpdate)
	assert.Equal(t, 0, opts.PruneAfterDays)
}
