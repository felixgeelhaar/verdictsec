package tui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultKeyMap(t *testing.T) {
	km := DefaultKeyMap()

	// Verify all key bindings are set
	assert.NotEmpty(t, km.Up.Keys())
	assert.NotEmpty(t, km.Down.Keys())
	assert.NotEmpty(t, km.PageUp.Keys())
	assert.NotEmpty(t, km.PageDown.Keys())
	assert.NotEmpty(t, km.Home.Keys())
	assert.NotEmpty(t, km.End.Keys())
	assert.NotEmpty(t, km.ToggleDetail.Keys())
	assert.NotEmpty(t, km.FocusList.Keys())
	assert.NotEmpty(t, km.FocusDetail.Keys())
	assert.NotEmpty(t, km.FilterCritical.Keys())
	assert.NotEmpty(t, km.FilterHigh.Keys())
	assert.NotEmpty(t, km.FilterMedium.Keys())
	assert.NotEmpty(t, km.FilterLow.Keys())
	assert.NotEmpty(t, km.ToggleNew.Keys())
	assert.NotEmpty(t, km.ToggleBaseline.Keys())
	assert.NotEmpty(t, km.ToggleSuppressed.Keys())
	assert.NotEmpty(t, km.ClearFilters.Keys())
	assert.NotEmpty(t, km.Search.Keys())
	assert.NotEmpty(t, km.ClearSearch.Keys())
	assert.NotEmpty(t, km.AddToBaseline.Keys())
	assert.NotEmpty(t, km.Help.Keys())
	assert.NotEmpty(t, km.Quit.Keys())
}

func TestKeyMap_ShortHelp(t *testing.T) {
	km := DefaultKeyMap()
	shortHelp := km.ShortHelp()

	assert.NotEmpty(t, shortHelp)
	assert.GreaterOrEqual(t, len(shortHelp), 3) // At least Up, Down, Quit
}

func TestKeyMap_FullHelp(t *testing.T) {
	km := DefaultKeyMap()
	fullHelp := km.FullHelp()

	assert.NotEmpty(t, fullHelp)
	assert.GreaterOrEqual(t, len(fullHelp), 4) // Multiple groups

	// Verify each group has bindings
	for i, group := range fullHelp {
		assert.NotEmpty(t, group, "Group %d should not be empty", i)
	}
}
