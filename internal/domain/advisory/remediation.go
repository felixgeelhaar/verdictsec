package advisory

import (
	"encoding/json"
	"time"
)

// RemediationPriority indicates the urgency of applying a remediation.
type RemediationPriority string

const (
	// PriorityCritical - fix immediately, active exploitation risk.
	PriorityCritical RemediationPriority = "critical"
	// PriorityHigh - fix in current sprint, significant risk.
	PriorityHigh RemediationPriority = "high"
	// PriorityMedium - plan fix in near future.
	PriorityMedium RemediationPriority = "medium"
	// PriorityLow - fix when convenient.
	PriorityLow RemediationPriority = "low"
)

// CodeSuggestion represents a suggested code change to remediate a finding.
type CodeSuggestion struct {
	Description string `json:"description"`
	FilePath    string `json:"file_path,omitempty"`
	LineStart   int    `json:"line_start,omitempty"`
	LineEnd     int    `json:"line_end,omitempty"`
	Original    string `json:"original,omitempty"`
	Replacement string `json:"replacement"`
	Language    string `json:"language,omitempty"`
}

// Remediation is a value object representing an AI-generated remediation
// suggestion for a security finding. It is immutable and advisory-only.
type Remediation struct {
	findingID       string
	priority        RemediationPriority
	summary         string
	steps           []string
	codeSuggestions []CodeSuggestion
	effort          string
	impact          string
	references      []string
	provider        string
	model           string
	generatedAt     time.Time
}

// RemediationOption is a functional option for creating remediations.
type RemediationOption func(*Remediation)

// NewRemediation creates a new remediation suggestion for a finding.
func NewRemediation(
	findingID string,
	priority RemediationPriority,
	summary string,
	provider string,
	model string,
	opts ...RemediationOption,
) *Remediation {
	r := &Remediation{
		findingID:       findingID,
		priority:        priority,
		summary:         summary,
		provider:        provider,
		model:           model,
		generatedAt:     time.Now().UTC(),
		steps:           make([]string, 0),
		codeSuggestions: make([]CodeSuggestion, 0),
		references:      make([]string, 0),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Functional options for remediation creation

// WithSteps sets the remediation steps.
func WithSteps(steps []string) RemediationOption {
	return func(r *Remediation) { r.steps = steps }
}

// WithCodeSuggestions sets the code change suggestions.
func WithCodeSuggestions(suggestions []CodeSuggestion) RemediationOption {
	return func(r *Remediation) { r.codeSuggestions = suggestions }
}

// WithEffort sets the estimated effort to implement the fix.
func WithEffort(effort string) RemediationOption {
	return func(r *Remediation) { r.effort = effort }
}

// WithImpact sets the expected impact of the remediation.
func WithImpact(impact string) RemediationOption {
	return func(r *Remediation) { r.impact = impact }
}

// WithRemediationReferences sets the reference URLs for the remediation.
func WithRemediationReferences(refs []string) RemediationOption {
	return func(r *Remediation) { r.references = refs }
}

// Getters - provide immutable access to remediation fields

// FindingID returns the ID of the finding this remediation is for.
func (r *Remediation) FindingID() string { return r.findingID }

// Priority returns the remediation priority.
func (r *Remediation) Priority() RemediationPriority { return r.priority }

// Summary returns a brief summary of the remediation.
func (r *Remediation) Summary() string { return r.summary }

// Steps returns the ordered remediation steps.
func (r *Remediation) Steps() []string { return r.steps }

// CodeSuggestions returns suggested code changes.
func (r *Remediation) CodeSuggestions() []CodeSuggestion { return r.codeSuggestions }

// Effort returns the estimated effort to implement.
func (r *Remediation) Effort() string { return r.effort }

// Impact returns the expected impact of remediation.
func (r *Remediation) Impact() string { return r.impact }

// References returns external reference URLs.
func (r *Remediation) References() []string { return r.references }

// Provider returns the AI provider that generated this remediation.
func (r *Remediation) Provider() string { return r.provider }

// Model returns the model ID used to generate this remediation.
func (r *Remediation) Model() string { return r.model }

// GeneratedAt returns when this remediation was generated.
func (r *Remediation) GeneratedAt() time.Time { return r.generatedAt }

// IsAdvisory always returns true - remediations are advisory only.
func (r *Remediation) IsAdvisory() bool { return true }

// HasCodeSuggestions returns true if code suggestions are available.
func (r *Remediation) HasCodeSuggestions() bool { return len(r.codeSuggestions) > 0 }

// remediationJSON is the JSON representation of a remediation.
type remediationJSON struct {
	FindingID       string              `json:"finding_id"`
	Priority        RemediationPriority `json:"priority"`
	Summary         string              `json:"summary"`
	Steps           []string            `json:"steps,omitempty"`
	CodeSuggestions []CodeSuggestion    `json:"code_suggestions,omitempty"`
	Effort          string              `json:"effort,omitempty"`
	Impact          string              `json:"impact,omitempty"`
	References      []string            `json:"references,omitempty"`
	Provider        string              `json:"provider"`
	Model           string              `json:"model"`
	GeneratedAt     time.Time           `json:"generated_at"`
	Advisory        bool                `json:"advisory"`
}

// MarshalJSON implements json.Marshaler.
func (r *Remediation) MarshalJSON() ([]byte, error) {
	return json.Marshal(remediationJSON{
		FindingID:       r.findingID,
		Priority:        r.priority,
		Summary:         r.summary,
		Steps:           r.steps,
		CodeSuggestions: r.codeSuggestions,
		Effort:          r.effort,
		Impact:          r.impact,
		References:      r.references,
		Provider:        r.provider,
		Model:           r.model,
		GeneratedAt:     r.generatedAt,
		Advisory:        true,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *Remediation) UnmarshalJSON(data []byte) error {
	var rj remediationJSON
	if err := json.Unmarshal(data, &rj); err != nil {
		return err
	}

	r.findingID = rj.FindingID
	r.priority = rj.Priority
	r.summary = rj.Summary
	r.steps = rj.Steps
	r.codeSuggestions = rj.CodeSuggestions
	r.effort = rj.Effort
	r.impact = rj.Impact
	r.references = rj.References
	r.provider = rj.Provider
	r.model = rj.Model
	r.generatedAt = rj.GeneratedAt

	if r.steps == nil {
		r.steps = make([]string, 0)
	}
	if r.codeSuggestions == nil {
		r.codeSuggestions = make([]CodeSuggestion, 0)
	}
	if r.references == nil {
		r.references = make([]string, 0)
	}

	return nil
}
