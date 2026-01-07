package writers

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
)

// HTMLWriter writes findings as an HTML report.
type HTMLWriter struct {
	out           io.Writer
	templateName  string
	title         string
	includeStyles bool
}

// HTMLOption configures the HTML writer.
type HTMLOption func(*HTMLWriter)

// WithHTMLOutput sets the output writer.
func WithHTMLOutput(out io.Writer) HTMLOption {
	return func(w *HTMLWriter) {
		w.out = out
	}
}

// WithHTMLTitle sets the report title.
func WithHTMLTitle(title string) HTMLOption {
	return func(w *HTMLWriter) {
		w.title = title
	}
}

// WithHTMLTemplate sets a custom template name.
func WithHTMLTemplate(name string) HTMLOption {
	return func(w *HTMLWriter) {
		w.templateName = name
	}
}

// WithHTMLStyles enables or disables inline styles.
func WithHTMLStyles(include bool) HTMLOption {
	return func(w *HTMLWriter) {
		w.includeStyles = include
	}
}

// NewHTMLWriter creates a new HTML writer.
func NewHTMLWriter(opts ...HTMLOption) *HTMLWriter {
	w := &HTMLWriter{
		out:           os.Stdout,
		templateName:  "report.html",
		title:         "VerdictSec Security Report",
		includeStyles: true,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// SetOutput sets the output destination.
func (w *HTMLWriter) SetOutput(out io.Writer) {
	w.out = out
}

// reportData holds data for the HTML template.
type reportData struct {
	Title         string
	GeneratedAt   string
	Target        string
	Duration      string
	Decision      string
	DecisionClass string
	IncludeStyles bool

	// Security Score
	ScoreValue       int
	ScoreGrade       string
	ScoreDescription string
	ScoreClass       string
	ScoreFactors     []scoreFactorData

	// Counts
	TotalFindings     int
	CriticalCount     int
	HighCount         int
	MediumCount       int
	LowCount          int
	NewCount          int
	BaselineCount     int
	SuppressedCount   int

	// Findings by category
	NewFindings      []findingData
	BaselineFindings []findingData
	SuppressedFindings []findingData

	// Engine runs
	EngineRuns []engineRunData
}

// scoreFactorData holds data for a score factor.
type scoreFactorData struct {
	Name       string
	Points     int
	PointsStr  string
	Reason     string
	IsPositive bool
}

// findingData holds data for a single finding.
type findingData struct {
	ID            string
	RuleID        string
	EngineID      string
	Title         string
	Severity      string
	SeverityClass string
	Confidence    string
	File          string
	Line          int
	Column        int
	CWE           string
	CVE           string
	Category      string
	Description   string
}

// engineRunData holds data for an engine run.
type engineRunData struct {
	Engine     string
	Status     string
	Duration   string
	FindingCount int
}

// WriteAssessment writes the assessment as an HTML report.
func (w *HTMLWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	data := w.buildReportData(a, result)
	return w.renderTemplate(data)
}

// WriteSummary writes a summary report.
func (w *HTMLWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	return w.WriteAssessment(a, result)
}

// WriteProgress writes progress messages (no-op for HTML).
func (w *HTMLWriter) WriteProgress(message string) error {
	return nil
}

// WriteError writes an error (no-op for HTML).
func (w *HTMLWriter) WriteError(err error) error {
	return nil
}

// Flush ensures all output is written.
func (w *HTMLWriter) Flush() error {
	return nil
}

// Close closes any resources.
func (w *HTMLWriter) Close() error {
	if closer, ok := w.out.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// buildReportData converts assessment to template data.
func (w *HTMLWriter) buildReportData(a *assessment.Assessment, result services.EvaluationResult) reportData {
	data := reportData{
		Title:         w.title,
		GeneratedAt:   time.Now().Format("2006-01-02 15:04:05"),
		Target:        a.Target(),
		Duration:      formatDuration(a.Duration()),
		Decision:      result.Decision.String(),
		DecisionClass: w.decisionClass(result.Decision),
		IncludeStyles: w.includeStyles,
	}

	// Build security score
	data.ScoreValue = result.Score.Value
	data.ScoreGrade = string(result.Score.Grade)
	data.ScoreDescription = result.Score.Grade.Description()
	data.ScoreClass = w.gradeClass(result.Score.Grade)
	for _, f := range result.Score.Factors {
		sign := "+"
		isPositive := true
		if f.Points < 0 {
			sign = ""
			isPositive = false
		}
		data.ScoreFactors = append(data.ScoreFactors, scoreFactorData{
			Name:       f.Name,
			Points:     f.Points,
			PointsStr:  fmt.Sprintf("%s%d", sign, f.Points),
			Reason:     f.Reason,
			IsPositive: isPositive,
		})
	}

	// Build summary counts
	summary := a.Summary()
	data.CriticalCount = summary[finding.SeverityCritical]
	data.HighCount = summary[finding.SeverityHigh]
	data.MediumCount = summary[finding.SeverityMedium]
	data.LowCount = summary[finding.SeverityLow]
	data.TotalFindings = len(a.Findings())

	// Categorize findings
	for _, f := range result.NewFindings {
		data.NewFindings = append(data.NewFindings, w.buildFindingData(f))
		data.NewCount++
	}
	for _, f := range result.Existing {
		data.BaselineFindings = append(data.BaselineFindings, w.buildFindingData(f))
		data.BaselineCount++
	}
	for _, f := range result.Suppressed {
		data.SuppressedFindings = append(data.SuppressedFindings, w.buildFindingData(f))
		data.SuppressedCount++
	}

	// Engine runs
	for _, run := range a.EngineRuns() {
		status := "success"
		if !run.Success() {
			status = "failed"
		}
		data.EngineRuns = append(data.EngineRuns, engineRunData{
			Engine:       run.EngineID(),
			Status:       status,
			Duration:     formatDuration(run.Duration()),
			FindingCount: run.FindingCount(),
		})
	}

	return data
}

// buildFindingData converts a finding to template data.
func (w *HTMLWriter) buildFindingData(f *finding.Finding) findingData {
	loc := f.Location()
	return findingData{
		ID:            f.Fingerprint().String(),
		RuleID:        f.RuleID(),
		EngineID:      string(f.EngineID()),
		Title:         f.Title(),
		Severity:      f.EffectiveSeverity().String(),
		SeverityClass: w.severityClass(f.EffectiveSeverity()),
		Confidence:    f.Confidence().String(),
		File:          loc.File(),
		Line:          loc.Line(),
		Column:        loc.Column(),
		CWE:           f.CWEID(),
		CVE:           f.CVEID(),
		Category:      f.Type().String(),
		Description:   f.Description(),
	}
}

// decisionClass returns CSS class for decision.
func (w *HTMLWriter) decisionClass(d assessment.Decision) string {
	switch d {
	case assessment.DecisionPass:
		return "pass"
	case assessment.DecisionWarn:
		return "warn"
	case assessment.DecisionFail:
		return "fail"
	default:
		return "unknown"
	}
}

// severityClass returns CSS class for severity.
func (w *HTMLWriter) severityClass(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "critical"
	case finding.SeverityHigh:
		return "high"
	case finding.SeverityMedium:
		return "medium"
	case finding.SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

// gradeClass returns CSS class for grade.
func (w *HTMLWriter) gradeClass(g services.Grade) string {
	switch g {
	case services.GradeA, services.GradeB:
		return "grade-good"
	case services.GradeC:
		return "grade-fair"
	case services.GradeD, services.GradeF:
		return "grade-poor"
	default:
		return ""
	}
}

// renderTemplate renders the HTML template.
func (w *HTMLWriter) renderTemplate(data reportData) error {
	// Try to load from embedded templates
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
	}).Parse(defaultTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	return tmpl.Execute(w.out, data)
}

// formatDuration formats a duration for display.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return d.Round(time.Millisecond).String()
}

// defaultTemplate is the embedded HTML template.
const defaultTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    {{if .IncludeStyles}}
    <style>
        :root {
            --color-critical: #dc2626;
            --color-high: #ea580c;
            --color-medium: #ca8a04;
            --color-low: #2563eb;
            --color-pass: #16a34a;
            --color-warn: #ca8a04;
            --color-fail: #dc2626;
            --color-bg: #f8fafc;
            --color-card: #ffffff;
            --color-border: #e2e8f0;
            --color-text: #1e293b;
            --color-muted: #64748b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--color-bg);
            color: var(--color-text);
            line-height: 1.5;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { font-size: 1.875rem; font-weight: 700; margin-bottom: 0.5rem; }
        h2 { font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; color: var(--color-text); }
        h3 { font-size: 1rem; font-weight: 600; margin-bottom: 0.5rem; }
        .subtitle { color: var(--color-muted); font-size: 0.875rem; margin-bottom: 2rem; }
        .card {
            background: var(--color-card);
            border: 1px solid var(--color-border);
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge.pass { background: #dcfce7; color: var(--color-pass); }
        .badge.warn { background: #fef9c3; color: var(--color-warn); }
        .badge.fail { background: #fee2e2; color: var(--color-fail); }
        .badge.critical { background: #fee2e2; color: var(--color-critical); }
        .badge.high { background: #ffedd5; color: var(--color-high); }
        .badge.medium { background: #fef9c3; color: var(--color-medium); }
        .badge.low { background: #dbeafe; color: var(--color-low); }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .stat {
            text-align: center;
            padding: 1rem;
            background: var(--color-bg);
            border-radius: 0.375rem;
        }
        .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-label { font-size: 0.75rem; color: var(--color-muted); text-transform: uppercase; }
        .stat.critical .stat-value { color: var(--color-critical); }
        .stat.high .stat-value { color: var(--color-high); }
        .stat.medium .stat-value { color: var(--color-medium); }
        .stat.low .stat-value { color: var(--color-low); }
        .score-card {
            display: flex;
            align-items: center;
            gap: 2rem;
            margin-bottom: 1.5rem;
        }
        .score-display {
            text-align: center;
            min-width: 120px;
        }
        .score-value {
            font-size: 3rem;
            font-weight: 700;
            line-height: 1;
        }
        .score-grade {
            display: inline-block;
            font-size: 1.5rem;
            font-weight: 700;
            width: 2.5rem;
            height: 2.5rem;
            line-height: 2.5rem;
            border-radius: 50%;
            margin-top: 0.5rem;
        }
        .grade-good .score-value { color: var(--color-pass); }
        .grade-good .score-grade { background: #dcfce7; color: var(--color-pass); }
        .grade-fair .score-value { color: var(--color-warn); }
        .grade-fair .score-grade { background: #fef9c3; color: var(--color-warn); }
        .grade-poor .score-value { color: var(--color-fail); }
        .grade-poor .score-grade { background: #fee2e2; color: var(--color-fail); }
        .score-factors {
            flex: 1;
        }
        .score-factor {
            display: flex;
            gap: 0.75rem;
            padding: 0.25rem 0;
            font-size: 0.875rem;
        }
        .factor-points {
            font-weight: 600;
            min-width: 3rem;
            text-align: right;
        }
        .factor-points.positive { color: var(--color-pass); }
        .factor-points.negative { color: var(--color-fail); }
        .finding {
            border: 1px solid var(--color-border);
            border-radius: 0.375rem;
            margin-bottom: 0.75rem;
            overflow: hidden;
        }
        .finding-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            background: var(--color-bg);
            cursor: pointer;
        }
        .finding-header:hover { background: #f1f5f9; }
        .finding-title { flex: 1; font-weight: 500; }
        .finding-meta { font-size: 0.75rem; color: var(--color-muted); }
        .finding-body {
            padding: 1rem;
            border-top: 1px solid var(--color-border);
            font-size: 0.875rem;
        }
        .finding-body dl {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 0.25rem 1rem;
        }
        .finding-body dt { font-weight: 500; color: var(--color-muted); }
        .finding-body dd { color: var(--color-text); }
        .engine-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.75rem;
        }
        .engine {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem;
            background: var(--color-bg);
            border-radius: 0.375rem;
        }
        .engine-status {
            width: 0.5rem;
            height: 0.5rem;
            border-radius: 50%;
        }
        .engine-status.success { background: var(--color-pass); }
        .engine-status.failed { background: var(--color-fail); }
        .section { margin-bottom: 2rem; }
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }
        .count {
            font-size: 0.875rem;
            color: var(--color-muted);
            background: var(--color-bg);
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
        }
        .empty { color: var(--color-muted); font-style: italic; }
        details summary { cursor: pointer; list-style: none; }
        details summary::-webkit-details-marker { display: none; }
        footer {
            text-align: center;
            color: var(--color-muted);
            font-size: 0.75rem;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--color-border);
        }
    </style>
    {{end}}
</head>
<body>
    <div class="container">
        <header>
            <h1>{{.Title}}</h1>
            <p class="subtitle">
                Target: {{.Target}} • Generated: {{.GeneratedAt}} • Duration: {{.Duration}}
            </p>
        </header>

        <div class="card">
            <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem;">
                <h2 style="margin: 0;">Security Score</h2>
                <span class="badge {{.DecisionClass}}">{{.Decision | upper}}</span>
            </div>
            <div class="score-card {{.ScoreClass}}">
                <div class="score-display">
                    <div class="score-value">{{.ScoreValue}}</div>
                    <div class="score-grade">{{.ScoreGrade}}</div>
                </div>
                {{if .ScoreFactors}}
                <div class="score-factors">
                    {{range .ScoreFactors}}
                    <div class="score-factor">
                        <span class="factor-points {{if .IsPositive}}positive{{else}}negative{{end}}">{{.PointsStr}}</span>
                        <span>{{.Reason}}</span>
                    </div>
                    {{end}}
                </div>
                {{end}}
            </div>
        </div>

        <div class="card">
            <h2>Severity Breakdown</h2>
            <div class="stats">
                <div class="stat critical">
                    <div class="stat-value">{{.CriticalCount}}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat high">
                    <div class="stat-value">{{.HighCount}}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat medium">
                    <div class="stat-value">{{.MediumCount}}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat low">
                    <div class="stat-value">{{.LowCount}}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{{.TotalFindings}}</div>
                    <div class="stat-label">Total</div>
                </div>
            </div>
        </div>

        {{if .EngineRuns}}
        <div class="card">
            <h2>Engine Runs</h2>
            <div class="engine-list">
                {{range .EngineRuns}}
                <div class="engine">
                    <span class="engine-status {{.Status}}"></span>
                    <span style="flex: 1;">{{.Engine}}</span>
                    <span style="font-size: 0.75rem; color: var(--color-muted);">{{.FindingCount}} findings • {{.Duration}}</span>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}

        {{if .NewFindings}}
        <div class="section">
            <div class="section-header">
                <h2>New Findings</h2>
                <span class="count">{{.NewCount}}</span>
            </div>
            {{range .NewFindings}}
            <details class="finding">
                <summary class="finding-header">
                    <span class="badge {{.SeverityClass}}">{{.Severity}}</span>
                    <span class="finding-title">{{.Title}}</span>
                    <span class="finding-meta">{{.File}}:{{.Line}}</span>
                </summary>
                <div class="finding-body">
                    <dl>
                        <dt>Rule</dt>
                        <dd>{{.RuleID}} ({{.EngineID}})</dd>
                        <dt>Location</dt>
                        <dd>{{.File}}:{{.Line}}:{{.Column}}</dd>
                        {{if .CWE}}<dt>CWE</dt><dd>{{.CWE}}</dd>{{end}}
                        {{if .CVE}}<dt>CVE</dt><dd>{{.CVE}}</dd>{{end}}
                        <dt>Category</dt>
                        <dd>{{.Category}}</dd>
                        <dt>Confidence</dt>
                        <dd>{{.Confidence}}</dd>
                        {{if .Description}}<dt>Description</dt><dd>{{.Description}}</dd>{{end}}
                    </dl>
                </div>
            </details>
            {{end}}
        </div>
        {{end}}

        {{if .BaselineFindings}}
        <div class="section">
            <div class="section-header">
                <h2>Baseline Findings</h2>
                <span class="count">{{.BaselineCount}}</span>
            </div>
            {{range .BaselineFindings}}
            <details class="finding">
                <summary class="finding-header">
                    <span class="badge {{.SeverityClass}}">{{.Severity}}</span>
                    <span class="finding-title">{{.Title}}</span>
                    <span class="finding-meta">{{.File}}:{{.Line}}</span>
                </summary>
                <div class="finding-body">
                    <dl>
                        <dt>Rule</dt>
                        <dd>{{.RuleID}} ({{.EngineID}})</dd>
                        <dt>Location</dt>
                        <dd>{{.File}}:{{.Line}}:{{.Column}}</dd>
                        {{if .CWE}}<dt>CWE</dt><dd>{{.CWE}}</dd>{{end}}
                        {{if .CVE}}<dt>CVE</dt><dd>{{.CVE}}</dd>{{end}}
                        <dt>Category</dt>
                        <dd>{{.Category}}</dd>
                        <dt>Confidence</dt>
                        <dd>{{.Confidence}}</dd>
                    </dl>
                </div>
            </details>
            {{end}}
        </div>
        {{end}}

        {{if .SuppressedFindings}}
        <div class="section">
            <div class="section-header">
                <h2>Suppressed Findings</h2>
                <span class="count">{{.SuppressedCount}}</span>
            </div>
            {{range .SuppressedFindings}}
            <details class="finding">
                <summary class="finding-header">
                    <span class="badge {{.SeverityClass}}">{{.Severity}}</span>
                    <span class="finding-title">{{.Title}}</span>
                    <span class="finding-meta">{{.File}}:{{.Line}}</span>
                </summary>
                <div class="finding-body">
                    <dl>
                        <dt>Rule</dt>
                        <dd>{{.RuleID}} ({{.EngineID}})</dd>
                        <dt>Location</dt>
                        <dd>{{.File}}:{{.Line}}:{{.Column}}</dd>
                    </dl>
                </div>
            </details>
            {{end}}
        </div>
        {{end}}

        {{if and (not .NewFindings) (not .BaselineFindings) (not .SuppressedFindings)}}
        <div class="card">
            <p class="empty">No security findings detected.</p>
        </div>
        {{end}}

        <footer>
            Generated by VerdictSec • {{.GeneratedAt}}
        </footer>
    </div>
</body>
</html>`

// Ensure HTMLWriter implements the interface.
var _ ports.ArtifactWriter = (*HTMLWriter)(nil)
