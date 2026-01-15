package tui

import "github.com/felixgeelhaar/verdictsec/internal/domain/finding"

// BaselineAddRequestMsg triggers the baseline dialog.
type BaselineAddRequestMsg struct {
	Finding *finding.Finding
}

// BaselineAddConfirmMsg confirms adding to baseline with reason.
type BaselineAddConfirmMsg struct {
	Finding *finding.Finding
	Reason  string
}

// BaselineAddResultMsg reports the result of baseline addition.
type BaselineAddResultMsg struct {
	Finding *finding.Finding
	Success bool
	Error   error
}

// StatusUpdateMsg updates the status bar message.
type StatusUpdateMsg struct {
	Message string
	IsError bool
}

// FilterChangedMsg signals that filters have changed.
type FilterChangedMsg struct{}

// ClearStatusMsg clears the status message after a delay.
type ClearStatusMsg struct{}
