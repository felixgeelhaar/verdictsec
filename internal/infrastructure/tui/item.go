package tui

import (
	"fmt"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// FindingItem wraps a Finding for display in the list.
type FindingItem struct {
	Finding *finding.Finding
	Status  string // "new", "baseline", "suppressed"
}

// Title returns the title for the list item.
// Implements list.Item interface.
func (f FindingItem) Title() string {
	sev := f.Finding.EffectiveSeverity().String()
	icon := StatusIcon(f.Status)
	return fmt.Sprintf("[%s] %s %s", sev, icon, f.Finding.Title())
}

// Description returns the description for the list item.
// Implements list.Item interface.
func (f FindingItem) Description() string {
	loc := f.Finding.Location()
	file := truncatePath(loc.File(), 30)
	return fmt.Sprintf("%s:%d [%s]", file, loc.Line(), f.Finding.EngineID())
}

// FilterValue returns the value to filter on.
// Implements list.Item interface.
func (f FindingItem) FilterValue() string {
	parts := []string{
		f.Finding.Title(),
		f.Finding.Description(),
		f.Finding.Location().File(),
		f.Finding.RuleID(),
		f.Finding.EngineID(),
	}
	if f.Finding.HasCVE() {
		parts = append(parts, f.Finding.CVEID())
	}
	if f.Finding.HasCWE() {
		parts = append(parts, f.Finding.CWEID())
	}
	return strings.Join(parts, " ")
}

// SeverityBadge returns a formatted severity badge.
func (f FindingItem) SeverityBadge() string {
	return fmt.Sprintf("[%s]", f.Finding.EffectiveSeverity().String())
}

// StatusString returns a human-readable status.
func (f FindingItem) StatusString() string {
	switch f.Status {
	case "new":
		return "NEW"
	case "baseline":
		return "BASELINE"
	case "suppressed":
		return "SUPPRESSED"
	default:
		return "UNKNOWN"
	}
}
