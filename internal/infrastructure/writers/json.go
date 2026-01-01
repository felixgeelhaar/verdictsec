package writers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/pkg/redact"
)

// JSONWriter writes JSON-formatted output.
type JSONWriter struct {
	out      io.Writer
	pretty   bool
	redactor *redact.Redactor
}

// JSONOption configures the JSON writer.
type JSONOption func(*JSONWriter)

// WithJSONOutput sets the output writer.
func WithJSONOutput(out io.Writer) JSONOption {
	return func(w *JSONWriter) {
		w.out = out
	}
}

// WithPrettyPrint enables pretty-printed JSON.
func WithPrettyPrint(enabled bool) JSONOption {
	return func(w *JSONWriter) {
		w.pretty = enabled
	}
}

// NewJSONWriter creates a new JSON writer.
func NewJSONWriter(opts ...JSONOption) *JSONWriter {
	w := &JSONWriter{
		out:      os.Stdout,
		pretty:   false,
		redactor: redact.New(redact.WithPartialDisplay(4, 4)),
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// SetOutput sets the output destination.
func (w *JSONWriter) SetOutput(out io.Writer) {
	w.out = out
}

// SetPretty enables or disables pretty-printed JSON.
func (w *JSONWriter) SetPretty(enabled bool) {
	w.pretty = enabled
}

// Close closes any open file handles.
func (w *JSONWriter) Close() error {
	if closer, ok := w.out.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// WriteAssessment writes the assessment as JSON.
func (w *JSONWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	output := w.buildOutput(a, result)
	return w.writeJSON(output)
}

// WriteSummary writes a brief summary as JSON.
func (w *JSONWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	summary := JSONSummary{
		Target:      a.Target(),
		Decision:    result.Decision.String(),
		TotalCount:  a.FindingCount(),
		NewCount:    len(result.NewFindings),
		ExistingCount: len(result.Existing),
		SuppressedCount: len(result.Suppressed),
		Duration:    a.Duration().String(),
	}
	return w.writeJSON(summary)
}

// WriteProgress writes a progress message.
func (w *JSONWriter) WriteProgress(message string) error {
	progress := JSONProgress{
		Type:      "progress",
		Message:   message,
		Timestamp: time.Now().UTC(),
	}
	return w.writeJSON(progress)
}

// WriteError writes an error message.
func (w *JSONWriter) WriteError(err error) error {
	errOutput := JSONError{
		Type:      "error",
		Message:   err.Error(),
		Timestamp: time.Now().UTC(),
	}
	return w.writeJSON(errOutput)
}

// Flush ensures all output is written.
func (w *JSONWriter) Flush() error {
	return nil
}

// buildOutput creates the full JSON output structure.
func (w *JSONWriter) buildOutput(a *assessment.Assessment, result services.EvaluationResult) JSONOutput {
	// Build findings with redacted secrets
	findings := make([]JSONFinding, len(a.Findings()))
	for i, f := range a.Findings() {
		findings[i] = w.buildFinding(f, result)
	}

	// Build engine runs
	engineRuns := make([]JSONEngineRun, len(a.EngineRuns()))
	for i, run := range a.EngineRuns() {
		engineRuns[i] = JSONEngineRun{
			EngineID:     run.EngineID(),
			Version:      run.EngineVersion(),
			StartedAt:    run.StartedAt(),
			Duration:     run.Duration().String(),
			Success:      run.Success(),
			Error:        run.ErrorMessage(),
			FindingCount: run.FindingCount(),
		}
	}

	// Build summary
	summary := a.Summary()
	severityCounts := map[string]int{
		"critical": summary[finding.SeverityCritical],
		"high":     summary[finding.SeverityHigh],
		"medium":   summary[finding.SeverityMedium],
		"low":      summary[finding.SeverityLow],
	}

	return JSONOutput{
		Version:     "1",
		AssessmentID: a.ID(),
		Target:      a.Target(),
		StartedAt:   a.StartedAt(),
		CompletedAt: a.CompletedAt(),
		Duration:    a.Duration().String(),
		Metadata:    a.Metadata(),
		EngineRuns:  engineRuns,
		Findings:    findings,
		Summary: JSONSummarySection{
			Total:          a.FindingCount(),
			BySeverity:     severityCounts,
			NewCount:       len(result.NewFindings),
			ExistingCount:  len(result.Existing),
			SuppressedCount: len(result.Suppressed),
		},
		Decision: JSONDecision{
			Result:  result.Decision.String(),
			Reasons: result.Reasons,
		},
	}
}

// buildFinding converts a finding to JSON format with redaction.
func (w *JSONWriter) buildFinding(f *finding.Finding, result services.EvaluationResult) JSONFinding {
	jf := JSONFinding{
		ID:          f.ID(),
		Type:        f.Type().String(),
		EngineID:    f.EngineID(),
		RuleID:      f.RuleID(),
		Title:       f.Title(),
		Description: f.Description(),
		Severity:    f.EffectiveSeverity().String(),
		Confidence:  f.Confidence().String(),
		Location: JSONLocation{
			File:      f.Location().File(),
			Line:      f.Location().Line(),
			Column:    f.Location().Column(),
			EndLine:   f.Location().EndLine(),
			EndColumn: f.Location().EndColumn(),
		},
		Fingerprint: f.Fingerprint().Value(),
		CWEID:       f.CWEID(),
		CVEID:       f.CVEID(),
		FixVersion:  f.FixVersion(),
	}

	// Determine status
	if isInSlice(f, result.Existing) {
		jf.Status = "baseline"
	} else if isInSlice(f, result.Suppressed) {
		jf.Status = "suppressed"
	} else {
		jf.Status = "new"
	}

	// Redact sensitive metadata
	metadata := f.Metadata()
	if metadata != nil && len(metadata) > 0 {
		jf.Metadata = w.redactor.RedactMap(metadata)
	}

	return jf
}

// writeJSON writes a value as JSON.
func (w *JSONWriter) writeJSON(v interface{}) error {
	var data []byte
	var err error

	if w.pretty {
		data, err = json.MarshalIndent(v, "", "  ")
	} else {
		data, err = json.Marshal(v)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	_, err = fmt.Fprintln(w.out, string(data))
	return err
}

// JSON output structures

// JSONOutput is the complete JSON output structure.
type JSONOutput struct {
	Version      string               `json:"version"`
	AssessmentID string               `json:"assessment_id"`
	Target       string               `json:"target"`
	StartedAt    time.Time            `json:"started_at"`
	CompletedAt  time.Time            `json:"completed_at"`
	Duration     string               `json:"duration"`
	Metadata     assessment.Metadata  `json:"metadata"`
	EngineRuns   []JSONEngineRun      `json:"engine_runs"`
	Findings     []JSONFinding        `json:"findings"`
	Summary      JSONSummarySection   `json:"summary"`
	Decision     JSONDecision         `json:"decision"`
}

// JSONEngineRun represents an engine run in JSON.
type JSONEngineRun struct {
	EngineID     string    `json:"engine_id"`
	Version      string    `json:"version"`
	StartedAt    time.Time `json:"started_at"`
	Duration     string    `json:"duration"`
	Success      bool      `json:"success"`
	Error        string    `json:"error,omitempty"`
	FindingCount int       `json:"finding_count"`
}

// JSONFinding represents a finding in JSON.
type JSONFinding struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	EngineID    string          `json:"engine_id"`
	RuleID      string          `json:"rule_id"`
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	Severity    string          `json:"severity"`
	Confidence  string          `json:"confidence"`
	Location    JSONLocation    `json:"location"`
	Fingerprint string          `json:"fingerprint"`
	Status      string          `json:"status"`
	CWEID       string          `json:"cwe_id,omitempty"`
	CVEID       string          `json:"cve_id,omitempty"`
	FixVersion  string          `json:"fix_version,omitempty"`
	Metadata    map[string]any  `json:"metadata,omitempty"`
}

// JSONLocation represents a code location in JSON.
type JSONLocation struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	EndLine   int    `json:"end_line,omitempty"`
	EndColumn int    `json:"end_column,omitempty"`
}

// JSONSummarySection is the summary section of the output.
type JSONSummarySection struct {
	Total           int            `json:"total"`
	BySeverity      map[string]int `json:"by_severity"`
	NewCount        int            `json:"new"`
	ExistingCount   int            `json:"existing"`
	SuppressedCount int            `json:"suppressed"`
}

// JSONDecision is the decision section of the output.
type JSONDecision struct {
	Result  string   `json:"result"`
	Reasons []string `json:"reasons"`
}

// JSONSummary is a brief summary output.
type JSONSummary struct {
	Target          string `json:"target"`
	Decision        string `json:"decision"`
	TotalCount      int    `json:"total_findings"`
	NewCount        int    `json:"new_findings"`
	ExistingCount   int    `json:"existing_findings"`
	SuppressedCount int    `json:"suppressed_findings"`
	Duration        string `json:"duration"`
}

// JSONProgress represents a progress message.
type JSONProgress struct {
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// JSONError represents an error message.
type JSONError struct {
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// Ensure JSONWriter implements the interface.
var _ ports.JSONWriter = (*JSONWriter)(nil)
