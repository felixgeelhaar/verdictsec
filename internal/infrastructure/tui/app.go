package tui

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	domainBaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// New creates a new TUI model from scan results.
func New(
	assess *assessment.Assessment,
	evalResult services.EvaluationResult,
	base *domainBaseline.Baseline,
	baselinePath string,
	colorEnabled bool,
) Model {
	styles := NewStyles(colorEnabled)
	keys := DefaultKeyMap()

	// Initialize filter state (show all by default)
	filterState := FilterState{
		Severities: map[finding.Severity]bool{
			finding.SeverityCritical: true,
			finding.SeverityHigh:     true,
			finding.SeverityMedium:   true,
			finding.SeverityLow:      true,
			finding.SeverityInfo:     true,
			finding.SeverityUnknown:  true,
		},
		Engines: make(map[string]bool),
		Types: map[finding.FindingType]bool{
			finding.FindingTypeSAST:    true,
			finding.FindingTypeVuln:    true,
			finding.FindingTypeSecret:  true,
			finding.FindingTypeSBOM:    true,
			finding.FindingTypeUnknown: true,
		},
		Status: StatusAll,
	}

	// Collect all unique engines and enable them
	for _, f := range assess.Findings() {
		filterState.Engines[f.EngineID()] = true
	}

	// Categorize findings by status
	allFindings := categorizeFindings(assess.Findings(), evalResult)

	// Initialize search input
	searchInput := textinput.New()
	searchInput.Placeholder = "Search findings..."
	searchInput.CharLimit = 100
	searchInput.Width = 40

	// Initialize baseline reason input
	baselineInput := textinput.New()
	baselineInput.Placeholder = "Enter reason for baselining..."
	baselineInput.CharLimit = 200
	baselineInput.Width = 45

	// Initialize list
	delegate := list.NewDefaultDelegate()
	findingList := list.New([]list.Item{}, delegate, 0, 0)
	findingList.SetShowTitle(false)
	findingList.SetShowStatusBar(false)
	findingList.SetFilteringEnabled(false)
	findingList.SetShowHelp(false)
	findingList.SetShowPagination(true)
	findingList.DisableQuitKeybindings()

	// Initialize viewport for detail panel
	detailViewport := viewport.New(0, 0)

	// Initialize help
	helpModel := help.New()
	helpModel.ShowAll = false

	m := Model{
		assessment:       assess,
		evalResult:       evalResult,
		baseline:         base,
		baselinePath:     baselinePath,
		allFindings:      allFindings,
		filteredFindings: allFindings,
		filterState:      filterState,
		findingList:      findingList,
		detailViewport:   detailViewport,
		searchInput:      searchInput,
		baselineInput:    baselineInput,
		help:             helpModel,
		viewMode:         ViewModeList,
		colorEnabled:     colorEnabled,
		styles:           styles,
		keys:             keys,
	}

	// Build initial list
	m.rebuildList()

	return m
}

// categorizeFindings assigns status to each finding based on evaluation result.
func categorizeFindings(findings []*finding.Finding, evalResult services.EvaluationResult) []FindingItem {
	// Build lookup maps for efficient categorization
	newMap := make(map[string]bool)
	for _, f := range evalResult.NewFindings {
		newMap[f.Fingerprint().Value()] = true
	}

	existingMap := make(map[string]bool)
	for _, f := range evalResult.Existing {
		existingMap[f.Fingerprint().Value()] = true
	}

	suppressedMap := make(map[string]bool)
	for _, f := range evalResult.Suppressed {
		suppressedMap[f.Fingerprint().Value()] = true
	}
	for _, f := range evalResult.InlineSuppressed {
		suppressedMap[f.Fingerprint().Value()] = true
	}

	// Categorize each finding
	items := make([]FindingItem, 0, len(findings))
	for _, f := range findings {
		fp := f.Fingerprint().Value()
		status := "new"

		if existingMap[fp] {
			status = "baseline"
		} else if suppressedMap[fp] {
			status = "suppressed"
		} else if newMap[fp] {
			status = "new"
		}

		items = append(items, FindingItem{
			Finding: f,
			Status:  status,
		})
	}

	return items
}
