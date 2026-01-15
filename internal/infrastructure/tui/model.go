package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	domainBaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/baseline"
)

// ViewMode represents the current UI focus.
type ViewMode int

const (
	ViewModeList ViewMode = iota
	ViewModeDetail
	ViewModeSearch
	ViewModeHelp
	ViewModeBaselineDialog
)

// StatusFilter represents the finding status filter.
type StatusFilter int

const (
	StatusAll StatusFilter = iota
	StatusNew
	StatusBaseline
	StatusSuppressed
)

// FilterState holds the current filter configuration.
type FilterState struct {
	Severities map[finding.Severity]bool
	Engines    map[string]bool
	Types      map[finding.FindingType]bool
	Status     StatusFilter
	Query      string
}

// Model is the main TUI application state.
type Model struct {
	// Data
	assessment   *assessment.Assessment
	evalResult   services.EvaluationResult
	baseline     *domainBaseline.Baseline
	baselinePath string

	// Findings
	allFindings      []FindingItem
	filteredFindings []FindingItem

	// UI Components
	findingList    list.Model
	detailViewport viewport.Model
	searchInput    textinput.Model
	baselineInput  textinput.Model
	help           help.Model

	// Baseline dialog state
	pendingBaselineFinding *finding.Finding

	// View state
	viewMode     ViewMode
	filterState  FilterState
	width        int
	height       int
	colorEnabled bool
	styles       Styles
	keys         KeyMap

	// Feedback
	statusMessage string
	errorMessage  string
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyMsg(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
		return m, nil

	case BaselineAddResultMsg:
		return m.handleBaselineResult(msg)

	case ClearStatusMsg:
		m.statusMessage = ""
		m.errorMessage = ""
		return m, nil
	}

	// Update child components
	if m.viewMode == ViewModeSearch {
		var cmd tea.Cmd
		m.searchInput, cmd = m.searchInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	if m.viewMode == ViewModeBaselineDialog {
		var cmd tea.Cmd
		m.baselineInput, cmd = m.baselineInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	if m.viewMode == ViewModeList {
		var cmd tea.Cmd
		m.findingList, cmd = m.findingList.Update(msg)
		cmds = append(cmds, cmd)
	}

	if m.viewMode == ViewModeDetail {
		var cmd tea.Cmd
		m.detailViewport, cmd = m.detailViewport.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// handleKeyMsg processes keyboard input.
func (m Model) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle search mode
	if m.viewMode == ViewModeSearch {
		switch {
		case key.Matches(msg, m.keys.ClearSearch):
			m.viewMode = ViewModeList
			m.searchInput.Reset()
			return m, nil
		case msg.Type == tea.KeyEnter:
			m.filterState.Query = m.searchInput.Value()
			m.applyFilters()
			m.viewMode = ViewModeList
			return m, nil
		default:
			var cmd tea.Cmd
			m.searchInput, cmd = m.searchInput.Update(msg)
			// Live filter as user types
			m.filterState.Query = m.searchInput.Value()
			m.applyFilters()
			return m, cmd
		}
	}

	// Handle baseline dialog mode
	if m.viewMode == ViewModeBaselineDialog {
		switch {
		case key.Matches(msg, m.keys.ClearSearch):
			m.viewMode = ViewModeList
			m.pendingBaselineFinding = nil
			m.baselineInput.Reset()
			return m, nil
		case msg.Type == tea.KeyEnter:
			reason := strings.TrimSpace(m.baselineInput.Value())
			if reason == "" {
				m.errorMessage = "Reason is required"
				return m, nil
			}
			return m.addToBaseline(m.pendingBaselineFinding, reason)
		default:
			var cmd tea.Cmd
			m.baselineInput, cmd = m.baselineInput.Update(msg)
			return m, cmd
		}
	}

	// Handle help mode
	if m.viewMode == ViewModeHelp {
		m.viewMode = ViewModeList
		return m, nil
	}

	// Normal mode key handling
	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit

	case key.Matches(msg, m.keys.Help):
		m.viewMode = ViewModeHelp
		return m, nil

	case key.Matches(msg, m.keys.Search):
		m.viewMode = ViewModeSearch
		m.searchInput.Focus()
		return m, nil

	case key.Matches(msg, m.keys.ToggleDetail):
		if m.viewMode == ViewModeList {
			m.viewMode = ViewModeDetail
		} else {
			m.viewMode = ViewModeList
		}
		return m, nil

	case key.Matches(msg, m.keys.FocusList):
		m.viewMode = ViewModeList
		return m, nil

	case key.Matches(msg, m.keys.FocusDetail):
		m.viewMode = ViewModeDetail
		m.updateDetailContent()
		return m, nil

	case key.Matches(msg, m.keys.FilterCritical):
		m.toggleSeverityFilter(finding.SeverityCritical)
		return m, nil

	case key.Matches(msg, m.keys.FilterHigh):
		m.toggleSeverityFilter(finding.SeverityHigh)
		return m, nil

	case key.Matches(msg, m.keys.FilterMedium):
		m.toggleSeverityFilter(finding.SeverityMedium)
		return m, nil

	case key.Matches(msg, m.keys.FilterLow):
		m.toggleSeverityFilter(finding.SeverityLow)
		return m, nil

	case key.Matches(msg, m.keys.ToggleNew):
		m.cycleStatusFilter(StatusNew)
		return m, nil

	case key.Matches(msg, m.keys.ToggleBaseline):
		m.cycleStatusFilter(StatusBaseline)
		return m, nil

	case key.Matches(msg, m.keys.ToggleSuppressed):
		m.cycleStatusFilter(StatusSuppressed)
		return m, nil

	case key.Matches(msg, m.keys.ClearFilters):
		m.clearFilters()
		return m, nil

	case key.Matches(msg, m.keys.AddToBaseline):
		return m.initiateBaselineAdd()

	case key.Matches(msg, m.keys.Up), key.Matches(msg, m.keys.Down),
		key.Matches(msg, m.keys.PageUp), key.Matches(msg, m.keys.PageDown),
		key.Matches(msg, m.keys.Home), key.Matches(msg, m.keys.End):
		if m.viewMode == ViewModeList {
			var cmd tea.Cmd
			m.findingList, cmd = m.findingList.Update(msg)
			m.updateDetailContent()
			return m, cmd
		} else if m.viewMode == ViewModeDetail {
			var cmd tea.Cmd
			m.detailViewport, cmd = m.detailViewport.Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

// View implements tea.Model.
func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	switch m.viewMode {
	case ViewModeHelp:
		return m.renderHelp()
	case ViewModeBaselineDialog:
		return m.renderBaselineDialog()
	default:
		return m.renderMainView()
	}
}

// renderMainView renders the main split-pane view.
func (m Model) renderMainView() string {
	// Calculate dimensions
	listWidth := m.width/2 - 2
	detailWidth := m.width - listWidth - 5
	contentHeight := m.height - 6

	// Render panels
	listPanel := m.renderListPanel(listWidth, contentHeight)
	detailPanel := m.renderDetailPanel(detailWidth, contentHeight)

	// Combine panels
	mainContent := lipgloss.JoinHorizontal(lipgloss.Top, listPanel, " ", detailPanel)

	// Render stats and help bars
	statsBar := m.renderStatsBar()
	helpBar := m.renderHelpBar()
	statusBar := m.renderStatusBar()

	return lipgloss.JoinVertical(lipgloss.Left, mainContent, statsBar, helpBar, statusBar)
}

// renderListPanel renders the finding list panel.
func (m Model) renderListPanel(width, height int) string {
	borderStyle := m.styles.BorderUnfocused
	if m.viewMode == ViewModeList || m.viewMode == ViewModeSearch {
		borderStyle = m.styles.BorderFocused
	}

	title := m.styles.Title.Render(fmt.Sprintf(" Findings (%d/%d) ",
		len(m.filteredFindings), len(m.allFindings)))

	content := m.findingList.View()

	// Add search bar if in search mode
	if m.viewMode == ViewModeSearch {
		searchBar := fmt.Sprintf("Search: %s", m.searchInput.View())
		content = searchBar + "\n" + content
	}

	return borderStyle.
		Width(width).
		Height(height).
		Render(title + "\n" + content)
}

// renderDetailPanel renders the finding detail panel.
func (m Model) renderDetailPanel(width, height int) string {
	borderStyle := m.styles.BorderUnfocused
	if m.viewMode == ViewModeDetail {
		borderStyle = m.styles.BorderFocused
	}

	title := m.styles.Title.Render(" Detail ")

	if len(m.filteredFindings) == 0 {
		content := m.styles.Dim.Render("No findings to display")
		return borderStyle.Width(width).Height(height).Render(title + "\n\n" + content)
	}

	return borderStyle.
		Width(width).
		Height(height).
		Render(title + "\n" + m.detailViewport.View())
}

// renderStatsBar renders the summary statistics bar.
func (m Model) renderStatsBar() string {
	summary := m.assessment.Summary()

	// Severity counts
	sevCounts := fmt.Sprintf(
		"%s:%d %s:%d %s:%d %s:%d",
		m.styles.Critical.Render("CRIT"), summary[finding.SeverityCritical],
		m.styles.High.Render("HIGH"), summary[finding.SeverityHigh],
		m.styles.Medium.Render("MED"), summary[finding.SeverityMedium],
		m.styles.Low.Render("LOW"), summary[finding.SeverityLow],
	)

	// Status counts
	statusCounts := fmt.Sprintf("New:%d Base:%d Supp:%d",
		len(m.evalResult.NewFindings),
		len(m.evalResult.Existing),
		len(m.evalResult.Suppressed)+len(m.evalResult.InlineSuppressed))

	// Score and decision
	scoreStr := ""
	if m.evalResult.Score.Value > 0 {
		scoreStr = fmt.Sprintf("%d(%s)",
			m.evalResult.Score.Value,
			m.styles.GradeStyle(m.evalResult.Score.Grade).Render(string(m.evalResult.Score.Grade)))
	}

	decisionStr := m.styles.DecisionStyle(m.evalResult.Decision).Render(m.evalResult.Decision.String())

	return m.styles.StatusBar.Render(
		fmt.Sprintf(" %s | %s | %s %s", sevCounts, statusCounts, scoreStr, decisionStr))
}

// renderHelpBar renders the keyboard shortcut hints.
func (m Model) renderHelpBar() string {
	filterInfo := ""
	if m.filterState.Status != StatusAll {
		switch m.filterState.Status {
		case StatusNew:
			filterInfo = " [new only]"
		case StatusBaseline:
			filterInfo = " [baseline only]"
		case StatusSuppressed:
			filterInfo = " [suppressed only]"
		}
	}

	return m.styles.Dim.Render(fmt.Sprintf(
		" %s severity | %s%s%s | %s search | %s baseline | %s help | %s quit%s",
		m.styles.HelpKey.Render("1-4"),
		m.styles.HelpKey.Render("n")+"ew ",
		m.styles.HelpKey.Render("e")+"xist ",
		m.styles.HelpKey.Render("s")+"upp",
		m.styles.HelpKey.Render("/"),
		m.styles.HelpKey.Render("b"),
		m.styles.HelpKey.Render("?"),
		m.styles.HelpKey.Render("q"),
		filterInfo,
	))
}

// renderStatusBar renders status/error messages.
func (m Model) renderStatusBar() string {
	if m.errorMessage != "" {
		return m.styles.Fail.Render(" " + m.errorMessage)
	}
	if m.statusMessage != "" {
		return m.styles.Dim.Render(" " + m.statusMessage)
	}
	return ""
}

// renderHelp renders the help overlay.
func (m Model) renderHelp() string {
	helpContent := `
 Navigation          Filtering           Actions
 ──────────          ─────────           ───────
 j/k, ↑/↓  move      1  CRITICAL         b  add to baseline
 g/G       first/last 2  HIGH            /  search
 pgup/pgdn page       3  MEDIUM          ?  this help
 tab/enter toggle     4  LOW             q  quit
 h/l       focus      n  new only
                      e  baseline only
                      s  suppressed only
                      c  clear filters

                   [Press any key to close]
`
	dialog := m.styles.Dialog.
		Width(60).
		Render(m.styles.Title.Render(" Keyboard Shortcuts ") + helpContent)

	// Overlay on main view
	return m.overlayCenter(m.renderMainView(), dialog)
}

// renderBaselineDialog renders the baseline addition dialog.
func (m Model) renderBaselineDialog() string {
	if m.pendingBaselineFinding == nil {
		return m.renderMainView()
	}

	f := m.pendingBaselineFinding

	content := fmt.Sprintf(`
%s

Finding: %s
Fingerprint: %s

Reason: %s

%s

    %s              %s`,
		m.styles.Title.Render("Add to Baseline"),
		f.Title(),
		f.Fingerprint().Short(),
		m.baselineInput.View(),
		m.styles.Dim.Render("A reason is required to document why this\nfinding is being added to the baseline."),
		m.styles.HelpKey.Render("[Enter]")+" Confirm",
		m.styles.HelpKey.Render("[Esc]")+" Cancel",
	)

	dialog := m.styles.Dialog.
		Width(55).
		Render(content)

	return m.overlayCenter(m.renderMainView(), dialog)
}

// overlayCenter centers an overlay on top of the background.
func (m Model) overlayCenter(background, overlay string) string {
	bgLines := strings.Split(background, "\n")
	ovLines := strings.Split(overlay, "\n")

	// Calculate overlay position
	startRow := (m.height - len(ovLines)) / 2
	startCol := (m.width - lipgloss.Width(overlay)) / 2

	// Overlay the dialog
	for i, ovLine := range ovLines {
		row := startRow + i
		if row >= 0 && row < len(bgLines) {
			bgLine := bgLines[row]
			// Pad background line if needed
			for len(bgLine) < startCol {
				bgLine += " "
			}
			// Insert overlay line
			if startCol >= 0 && startCol < len(bgLine) {
				bgLines[row] = bgLine[:startCol] + ovLine
			}
		}
	}

	return strings.Join(bgLines, "\n")
}

// updateLayout updates component sizes after window resize.
func (m *Model) updateLayout() {
	listWidth := m.width/2 - 4
	detailWidth := m.width - listWidth - 8
	contentHeight := m.height - 8

	m.findingList.SetSize(listWidth, contentHeight)
	m.detailViewport.Width = detailWidth
	m.detailViewport.Height = contentHeight

	m.updateDetailContent()
}

// updateDetailContent updates the detail viewport with current selection.
func (m *Model) updateDetailContent() {
	if len(m.filteredFindings) == 0 {
		m.detailViewport.SetContent("No findings selected")
		return
	}

	idx := m.findingList.Index()
	if idx < 0 || idx >= len(m.filteredFindings) {
		return
	}

	item := m.filteredFindings[idx]
	f := item.Finding

	var b strings.Builder

	// Title and status
	b.WriteString(m.styles.SeverityStyle(f.EffectiveSeverity()).Render(
		fmt.Sprintf("[%s]", f.EffectiveSeverity())))
	b.WriteString(" " + m.styles.Bold.Render(f.Title()) + "\n")
	b.WriteString("Status: " + m.styles.StatusStyle(item.Status).Render(
		StatusIcon(item.Status)+" "+item.StatusString()) + "\n\n")

	// Basic info
	b.WriteString(m.styles.Dim.Render("Type:     ") + f.Type().String() + "\n")
	b.WriteString(m.styles.Dim.Render("Engine:   ") + f.EngineID() + "\n")
	b.WriteString(m.styles.Dim.Render("Rule:     ") + f.RuleID() + "\n\n")

	// Location
	b.WriteString(m.styles.Subtitle.Render("Location") + "\n")
	b.WriteString(m.styles.Dim.Render("File:   ") + f.Location().File() + "\n")
	b.WriteString(m.styles.Dim.Render("Line:   ") + fmt.Sprintf("%d:%d",
		f.Location().Line(), f.Location().Column()) + "\n\n")

	// Description
	if f.Description() != "" {
		b.WriteString(m.styles.Subtitle.Render("Description") + "\n")
		b.WriteString(wrapText(f.Description(), m.detailViewport.Width-4) + "\n\n")
	}

	// CVE/CWE/Fix
	if f.HasCVE() {
		b.WriteString(m.styles.Dim.Render("CVE: ") + f.CVEID() + "\n")
	}
	if f.HasCWE() {
		b.WriteString(m.styles.Dim.Render("CWE: ") + f.CWEID() + "\n")
	}
	if f.HasFix() {
		b.WriteString(m.styles.Dim.Render("Fix: ") + f.FixVersion() + "\n")
	}

	// Fingerprint
	b.WriteString("\n" + m.styles.Dim.Render("Fingerprint: ") + f.Fingerprint().Short() + "\n")

	// Action hint
	if item.Status == "new" {
		b.WriteString("\n" + m.styles.Dim.Render("[Press 'b' to add to baseline]"))
	}

	m.detailViewport.SetContent(b.String())
}

// toggleSeverityFilter toggles a severity filter.
func (m *Model) toggleSeverityFilter(sev finding.Severity) {
	m.filterState.Severities[sev] = !m.filterState.Severities[sev]
	m.applyFilters()
}

// cycleStatusFilter cycles through status filters.
func (m *Model) cycleStatusFilter(target StatusFilter) {
	if m.filterState.Status == target {
		m.filterState.Status = StatusAll
	} else {
		m.filterState.Status = target
	}
	m.applyFilters()
}

// clearFilters resets all filters to default (show all).
func (m *Model) clearFilters() {
	for k := range m.filterState.Severities {
		m.filterState.Severities[k] = true
	}
	m.filterState.Status = StatusAll
	m.filterState.Query = ""
	m.searchInput.Reset()
	m.applyFilters()
}

// applyFilters filters allFindings based on filterState.
func (m *Model) applyFilters() {
	m.filteredFindings = make([]FindingItem, 0, len(m.allFindings))

	query := strings.ToLower(m.filterState.Query)

	for _, item := range m.allFindings {
		// Check severity filter
		if !m.filterState.Severities[item.Finding.EffectiveSeverity()] {
			continue
		}

		// Check status filter
		if m.filterState.Status != StatusAll {
			switch m.filterState.Status {
			case StatusNew:
				if item.Status != "new" {
					continue
				}
			case StatusBaseline:
				if item.Status != "baseline" {
					continue
				}
			case StatusSuppressed:
				if item.Status != "suppressed" {
					continue
				}
			}
		}

		// Check search query
		if query != "" {
			filterVal := strings.ToLower(item.FilterValue())
			if !strings.Contains(filterVal, query) {
				continue
			}
		}

		m.filteredFindings = append(m.filteredFindings, item)
	}

	m.rebuildList()
}

// rebuildList rebuilds the list model from filtered findings.
func (m *Model) rebuildList() {
	items := make([]list.Item, len(m.filteredFindings))
	for i, item := range m.filteredFindings {
		items[i] = item
	}
	m.findingList.SetItems(items)
	m.updateDetailContent()
}

// initiateBaselineAdd starts the baseline addition process.
func (m Model) initiateBaselineAdd() (Model, tea.Cmd) {
	if len(m.filteredFindings) == 0 {
		m.errorMessage = "No finding selected"
		return m, nil
	}

	idx := m.findingList.Index()
	if idx < 0 || idx >= len(m.filteredFindings) {
		return m, nil
	}

	item := m.filteredFindings[idx]
	if item.Status == "baseline" {
		m.statusMessage = "Finding is already in baseline"
		return m, nil
	}
	if item.Status == "suppressed" {
		m.statusMessage = "Finding is already suppressed"
		return m, nil
	}

	m.viewMode = ViewModeBaselineDialog
	m.pendingBaselineFinding = item.Finding
	m.baselineInput.Reset()
	m.baselineInput.Focus()

	return m, nil
}

// addToBaseline adds the finding to the baseline.
func (m Model) addToBaseline(f *finding.Finding, reason string) (Model, tea.Cmd) {
	// Add to baseline
	if m.baseline == nil {
		m.baseline = domainBaseline.NewBaseline("")
	}

	err := m.baseline.Add(f, reason)
	if err != nil {
		m.errorMessage = fmt.Sprintf("Failed to add to baseline: %v", err)
		m.viewMode = ViewModeList
		m.pendingBaselineFinding = nil
		return m, nil
	}

	// Save baseline
	store := baseline.NewStoreWithPath(m.baselinePath)
	if err := store.Save(m.baseline); err != nil {
		m.errorMessage = fmt.Sprintf("Failed to save baseline: %v", err)
		m.viewMode = ViewModeList
		m.pendingBaselineFinding = nil
		return m, nil
	}

	// Update finding status in our lists
	fp := f.Fingerprint().Value()
	for i := range m.allFindings {
		if m.allFindings[i].Finding.Fingerprint().Value() == fp {
			m.allFindings[i].Status = "baseline"
		}
	}

	// Move from new to existing in eval result
	m.evalResult.Existing = append(m.evalResult.Existing, f)
	newFindings := make([]*finding.Finding, 0, len(m.evalResult.NewFindings)-1)
	for _, nf := range m.evalResult.NewFindings {
		if nf.Fingerprint().Value() != fp {
			newFindings = append(newFindings, nf)
		}
	}
	m.evalResult.NewFindings = newFindings

	m.statusMessage = fmt.Sprintf("Added %s to baseline", f.Fingerprint().Short())
	m.viewMode = ViewModeList
	m.pendingBaselineFinding = nil
	m.baselineInput.Reset()
	m.applyFilters()

	return m, nil
}

// handleBaselineResult handles the result of a baseline addition.
func (m Model) handleBaselineResult(msg BaselineAddResultMsg) (Model, tea.Cmd) {
	if msg.Success {
		m.statusMessage = fmt.Sprintf("Added %s to baseline", msg.Finding.Fingerprint().Short())
	} else {
		m.errorMessage = fmt.Sprintf("Failed to add to baseline: %v", msg.Error)
	}
	return m, nil
}
