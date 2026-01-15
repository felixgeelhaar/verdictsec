package tui

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines all key bindings for the TUI.
type KeyMap struct {
	// Navigation
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Home     key.Binding
	End      key.Binding

	// View switching
	ToggleDetail key.Binding
	FocusList    key.Binding
	FocusDetail  key.Binding

	// Filtering
	FilterCritical   key.Binding
	FilterHigh       key.Binding
	FilterMedium     key.Binding
	FilterLow        key.Binding
	ToggleNew        key.Binding
	ToggleBaseline   key.Binding
	ToggleSuppressed key.Binding
	ClearFilters     key.Binding

	// Search
	Search      key.Binding
	ClearSearch key.Binding

	// Actions
	AddToBaseline key.Binding

	// General
	Help key.Binding
	Quit key.Binding
}

// DefaultKeyMap returns the default key bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup", "ctrl+u"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown", "ctrl+d"),
			key.WithHelp("pgdn", "page down"),
		),
		Home: key.NewBinding(
			key.WithKeys("home", "g"),
			key.WithHelp("home/g", "first"),
		),
		End: key.NewBinding(
			key.WithKeys("end", "G"),
			key.WithHelp("end/G", "last"),
		),

		ToggleDetail: key.NewBinding(
			key.WithKeys("enter", "tab"),
			key.WithHelp("enter/tab", "toggle detail"),
		),
		FocusList: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("←/h", "list"),
		),
		FocusDetail: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("→/l", "detail"),
		),

		FilterCritical: key.NewBinding(
			key.WithKeys("1"),
			key.WithHelp("1", "toggle CRITICAL"),
		),
		FilterHigh: key.NewBinding(
			key.WithKeys("2"),
			key.WithHelp("2", "toggle HIGH"),
		),
		FilterMedium: key.NewBinding(
			key.WithKeys("3"),
			key.WithHelp("3", "toggle MEDIUM"),
		),
		FilterLow: key.NewBinding(
			key.WithKeys("4"),
			key.WithHelp("4", "toggle LOW"),
		),
		ToggleNew: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "new only"),
		),
		ToggleBaseline: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "baseline only"),
		),
		ToggleSuppressed: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "suppressed only"),
		),
		ClearFilters: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "clear filters"),
		),

		Search: key.NewBinding(
			key.WithKeys("/"),
			key.WithHelp("/", "search"),
		),
		ClearSearch: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "clear/cancel"),
		),

		AddToBaseline: key.NewBinding(
			key.WithKeys("b"),
			key.WithHelp("b", "add to baseline"),
		),

		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}
}

// ShortHelp returns keybindings to be shown in the mini help view.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.ToggleDetail, k.Search, k.Help, k.Quit}
}

// FullHelp returns keybindings for the expanded help view.
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.PageUp, k.PageDown, k.Home, k.End},
		{k.ToggleDetail, k.FocusList, k.FocusDetail},
		{k.FilterCritical, k.FilterHigh, k.FilterMedium, k.FilterLow},
		{k.ToggleNew, k.ToggleBaseline, k.ToggleSuppressed, k.ClearFilters},
		{k.Search, k.AddToBaseline, k.Help, k.Quit},
	}
}
