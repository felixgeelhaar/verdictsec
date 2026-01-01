package assessment

import (
	"time"
)

// EngineRun represents a single engine execution within an assessment.
// It captures metadata about the engine run for auditability.
type EngineRun struct {
	engineID      string
	engineVersion string
	startedAt     time.Time
	completedAt   time.Time
	success       bool
	errorMessage  string
	findingCount  int
	// Evidence fields for debugging and audit
	rawOutput    []byte
	outputFormat string
}

// NewEngineRun creates a new EngineRun.
func NewEngineRun(engineID, engineVersion string) *EngineRun {
	return &EngineRun{
		engineID:      engineID,
		engineVersion: engineVersion,
		startedAt:     time.Now().UTC(),
	}
}

// EngineID returns the engine identifier.
func (r *EngineRun) EngineID() string { return r.engineID }

// EngineVersion returns the engine version.
func (r *EngineRun) EngineVersion() string { return r.engineVersion }

// StartedAt returns when the engine run started.
func (r *EngineRun) StartedAt() time.Time { return r.startedAt }

// CompletedAt returns when the engine run completed.
func (r *EngineRun) CompletedAt() time.Time { return r.completedAt }

// Duration returns the duration of the engine run.
func (r *EngineRun) Duration() time.Duration {
	if r.completedAt.IsZero() {
		return 0
	}
	return r.completedAt.Sub(r.startedAt)
}

// Success returns true if the engine run completed successfully.
func (r *EngineRun) Success() bool { return r.success }

// ErrorMessage returns the error message if the run failed.
func (r *EngineRun) ErrorMessage() string { return r.errorMessage }

// FindingCount returns the number of findings detected.
func (r *EngineRun) FindingCount() int { return r.findingCount }

// RawOutput returns the raw engine output for debugging.
func (r *EngineRun) RawOutput() []byte { return r.rawOutput }

// OutputFormat returns the format of the raw output (e.g., "json", "sarif").
func (r *EngineRun) OutputFormat() string { return r.outputFormat }

// SetEvidence stores the raw engine output for audit purposes.
func (r *EngineRun) SetEvidence(rawOutput []byte, format string) {
	r.rawOutput = rawOutput
	r.outputFormat = format
}

// Complete marks the engine run as completed successfully.
func (r *EngineRun) Complete(findingCount int) {
	r.completedAt = time.Now().UTC()
	r.success = true
	r.findingCount = findingCount
}

// Fail marks the engine run as failed.
func (r *EngineRun) Fail(err error) {
	r.completedAt = time.Now().UTC()
	r.success = false
	if err != nil {
		r.errorMessage = err.Error()
	}
}

// EngineRunData is the serializable representation of an EngineRun.
type EngineRunData struct {
	EngineID      string    `json:"engine_id"`
	EngineVersion string    `json:"engine_version"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	DurationMs    int64     `json:"duration_ms"`
	Success       bool      `json:"success"`
	ErrorMessage  string    `json:"error_message,omitempty"`
	FindingCount  int       `json:"finding_count"`
	OutputFormat  string    `json:"output_format,omitempty"`
	// RawOutput is excluded from JSON to avoid bloat; access via API if needed
}

// ToData converts an EngineRun to its serializable form.
func (r *EngineRun) ToData() EngineRunData {
	return EngineRunData{
		EngineID:      r.engineID,
		EngineVersion: r.engineVersion,
		StartedAt:     r.startedAt,
		CompletedAt:   r.completedAt,
		DurationMs:    r.Duration().Milliseconds(),
		Success:       r.success,
		ErrorMessage:  r.errorMessage,
		FindingCount:  r.findingCount,
		OutputFormat:  r.outputFormat,
	}
}

// EngineRunFromData creates an EngineRun from its serializable form.
func EngineRunFromData(data EngineRunData) *EngineRun {
	return &EngineRun{
		engineID:      data.EngineID,
		engineVersion: data.EngineVersion,
		startedAt:     data.StartedAt,
		completedAt:   data.CompletedAt,
		success:       data.Success,
		errorMessage:  data.ErrorMessage,
		findingCount:  data.FindingCount,
		outputFormat:  data.OutputFormat,
	}
}
